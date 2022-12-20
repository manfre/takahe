import string

from django import forms
from django.core import validators
from django.db import models
from django.shortcuts import get_object_or_404, redirect
from django.utils.decorators import method_decorator
from django.views.generic import FormView, ListView

from core.models import Config
from users.decorators import admin_required, moderator_required
from users.models import Domain, Identity, IdentityStates


@method_decorator(moderator_required, name="dispatch")
class IdentitiesRoot(ListView):

    template_name = "admin/identities.html"
    paginate_by = 30

    def get(self, request, *args, **kwargs):
        self.query = request.GET.get("query")
        self.local_only = request.GET.get("local_only")
        self.extra_context = {
            "section": "identities",
            "query": self.query or "",
            "local_only": self.local_only,
        }
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        identities = Identity.objects.annotate(
            num_users=models.Count("users")
        ).order_by("created")
        if self.local_only:
            identities = identities.filter(local=True)
        if self.query:
            query = self.query.lower().strip().lstrip("@")
            if "@" in query:
                username, domain = query.split("@", 1)
                identities = identities.filter(
                    username__iexact=username,
                    domain__domain__istartswith=domain,
                )
            else:
                identities = identities.filter(
                    models.Q(username__icontains=self.query)
                    | models.Q(name__icontains=self.query)
                )
        return identities


@method_decorator(moderator_required, name="dispatch")
class IdentityEdit(FormView):

    template_name = "admin/identity_edit.html"
    extra_context = {
        "section": "identities",
    }

    class form_class(forms.Form):
        notes = forms.CharField(widget=forms.Textarea, required=False)

    def dispatch(self, request, id, *args, **kwargs):
        self.identity = get_object_or_404(Identity, id=id)
        return super().dispatch(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        if "fetch" in request.POST:
            self.identity.transition_perform(IdentityStates.outdated)
            self.identity = Identity.objects.get(pk=self.identity.pk)
        if "limit" in request.POST:
            self.identity.restriction = Identity.Restriction.limited
            self.identity.save()
        if "block" in request.POST:
            self.identity.restriction = Identity.Restriction.blocked
            self.identity.save()
        if "unlimit" in request.POST or "unblock" in request.POST:
            self.identity.restriction = Identity.Restriction.none
            self.identity.save()
        return super().post(request, *args, **kwargs)

    def get_initial(self):
        return {"notes": self.identity.admin_notes}

    def form_valid(self, form):
        self.identity.admin_notes = form.cleaned_data["notes"]
        self.identity.save()
        return redirect(".")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["identity"] = self.identity
        return context


@method_decorator(admin_required, name="dispatch")
class IdentityLocalMove(FormView):

    template_name = "admin/identity_move.html"
    extra_context = {
        "section": "identities",
    }

    class form_class(forms.Form):
        handle = forms.CharField(
            help_text="Are you sure? Enter the current Identity handle."
        )
        username = forms.CharField(
            help_text="Must be unique on the destination domain. Use only: a-z 0-9 _ -"
        )
        domain = forms.ChoiceField(
            help_text="Pick the new domain for the identity, if changing. Leave empty if only renaming username."
        )

        def __init__(self, identity, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.identity = identity
            self.user = identity.users.first()
            self.fields["domain"].choices = [
                (domain.domain, domain.domain)
                for domain in Domain.available_for_user(self.user)
            ]

        def clean_handle(self):
            # Remove any leading @ and force it lowercase
            value = self.cleaned_data["handle"].lstrip("@").lower()
            if value != f"{self.identity.username}@{self.identity.domain_id}":
                raise forms.ValidationError("You must enter the existing handle")
            return value

        def clean_username(self):
            # Remove any leading @ and force it lowercase
            value = self.cleaned_data["username"].lstrip("@").lower()

            if not self.user.admin:
                # Apply username min length
                limit = int(Config.system.identity_min_length)
                validators.MinLengthValidator(limit)(value)

                # Apply username restrictions
                if value in Config.system.restricted_usernames.split():
                    raise forms.ValidationError(
                        "This username is restricted to administrators only."
                    )
                if value in ["__system__"]:
                    raise forms.ValidationError(
                        "This username is reserved for system use."
                    )

            # Validate it's all ascii characters
            for character in value:
                if character not in string.ascii_letters + string.digits + "_-":
                    raise forms.ValidationError(
                        "Only the letters a-z, numbers 0-9, dashes, and underscores are allowed."
                    )
            return value

        def clean(self):
            # Check for existing users
            username = self.cleaned_data.get("username")
            domain = self.cleaned_data.get("domain")
            if (
                username
                and domain
                and Identity.objects.filter(username=username, domain=domain).exists()
            ):
                raise forms.ValidationError(f"{username}@{domain} is already taken")

            if username == self.identity.username and domain == self.identity.domain_id:
                raise forms.ValidationError("Username and domain are unchanged")

    def dispatch(self, request, id, *args, **kwargs):
        self.identity = get_object_or_404(Identity, id=id)
        return super().dispatch(request, *args, **kwargs)

    def get_form(self):
        form_class = self.get_form_class()
        return form_class(identity=self.identity, **self.get_form_kwargs())

    def get_initial(self):
        return {
            "username": self.identity.username,
            "domain": self.identity.domain,
        }

    def form_valid(self, form):
        # DO THE MOVE
        self.identity.username = form.cleaned_data["username"]
        domain = form.cleaned_data["domain"]
        self.identity.domain = Domain.get_domain(domain)
        # self.identity.previous_actor_uri = self.identity.previous_actor_uri
        self.identity.save()
        self.identity.transition_perform(IdentityStates.moved)
        return redirect(".")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["identity"] = self.identity
        return context
