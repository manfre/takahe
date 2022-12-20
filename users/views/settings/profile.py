from django import forms
from django.core.files import File
from django.http import Http404
from django.shortcuts import redirect
from django.utils.decorators import method_decorator
from django.views.generic import FormView

from core.files import resize_image
from core.html import html_to_plaintext
from core.models.config import Config
from users.decorators import identity_required
from users.models import Identity, IdentityStates
from users.services import IdentityService
from users.shortcuts import by_handle_or_404


@method_decorator(identity_required, name="dispatch")
class ProfilePage(FormView):
    """
    Lets the identity's profile be edited
    """

    template_name = "settings/profile.html"
    extra_context = {"section": "profile"}

    class form_class(forms.Form):
        name = forms.CharField(max_length=500)
        summary = forms.CharField(
            widget=forms.Textarea,
            required=False,
            help_text="Describe you and your interests",
            label="Bio",
        )
        icon = forms.ImageField(
            required=False, help_text="Shown next to all your posts and activities"
        )
        image = forms.ImageField(
            required=False, help_text="Shown at the top of your profile"
        )
        discoverable = forms.BooleanField(
            help_text="If this user is visible on the frontpage and in user directories.",
            widget=forms.Select(
                choices=[(True, "Discoverable"), (False, "Not Discoverable")]
            ),
            required=False,
        )
        visible_follows = forms.BooleanField(
            help_text="Whether or not to show your following and follower counts in your profile.",
            widget=forms.Select(choices=[(True, "Visible"), (False, "Hidden")]),
            required=False,
        )

    def get_initial(self):
        identity = self.request.identity
        return {
            "name": identity.name,
            "summary": html_to_plaintext(identity.summary) if identity.summary else "",
            "icon": identity.icon and identity.icon.url,
            "image": identity.image and identity.image.url,
            "discoverable": identity.discoverable,
            "visible_follows": identity.config_identity.visible_follows,
        }

    def form_valid(self, form):
        # Update basic info
        identity = self.request.identity
        identity.name = form.cleaned_data["name"]
        identity.discoverable = form.cleaned_data["discoverable"]
        IdentityService(identity).set_summary(form.cleaned_data["summary"])
        # Resize images
        icon = form.cleaned_data.get("icon")
        image = form.cleaned_data.get("image")
        if isinstance(icon, File):
            identity.icon.save(
                icon.name,
                resize_image(icon, size=(400, 400)),
            )
        if isinstance(image, File):
            identity.image.save(
                image.name,
                resize_image(image, size=(1500, 500)),
            )
        identity.save()
        identity.transition_perform(IdentityStates.edited)

        # Save profile-specific identity Config
        Config.set_identity(
            identity, "visible_follows", form.cleaned_data["visible_follows"]
        )
        return redirect(".")


from django.forms import widgets


class HiddenClearButtonInput(widgets.Input):
    input_type = "hidden"
    template_name = "forms/widgets/_hidden_with_button.html"


class MultipleAliasesWidget(forms.MultiWidget):
    def decompress(self, value):
        import json

        return json.loads(value)


class MultipleAliasesField(forms.MultiValueField):
    def compress(self, data_list):
        import json

        return json.dumps(data_list)


@method_decorator(identity_required, name="dispatch")
class ProfileAliasesPage(FormView):

    template_name = "settings/profile_aliases.html"
    extra_context = {"section": "profile", "sub_section": "profile-aliases"}

    class form_class(forms.Form):
        handle = forms.CharField(
            required=False, help_text="Enter the handle of your other account."
        )
        aliases = MultipleAliasesField(
            widget=MultipleAliasesWidget(widgets=[]),
            fields=[],
            show_hidden_initial=True,
            label="",
            required=False,
        )

        def __init__(self, request, identity, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.request = request
            self.fields["aliases"].fields = [
                forms.CharField() for aka in identity.also_known_as
            ]
            self.fields["aliases"].widget = MultipleAliasesWidget(
                widgets=[HiddenClearButtonInput() for aka in identity.also_known_as]
            )
            self.identity = identity
            self.user = identity.users.first()

        def clean_handle(self):
            # Remove any leading @ and force it lowercase
            value = self.cleaned_data["handle"].lstrip("@").lower()
            if "@" not in value:
                raise forms.ValidationError(
                    "You must enter the full handle. username@domain"
                )
            try:
                by_handle_or_404(self.request, value, local=False, fetch=True)
            except Http404:
                raise forms.ValidationError("Unable to fetch identity")
            return value

    def post(self, request, *args, **kwargs):
        if "delete" in request.POST:
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
        data = super().get_initial()
        if self.identity.also_known_as:
            data.update(
                {
                    "aliases": list(self.identity.also_known_as),
                    # "aliases": ["a", "b", "c"]
                }
            )
        return data

    def dispatch(self, request, *args, **kwargs):
        self.identity = self.request.identity
        return super().dispatch(request, *args, **kwargs)

    def get_form(self):
        form_class = self.get_form_class()
        return form_class(
            request=self.request, identity=self.identity, **self.get_form_kwargs()
        )

    def form_valid(self, form):
        # Add the alias
        if form.cleaned_data["handle"]:
            aka = self.identity.also_known_as
            if not aka:
                aka = []
            aka.append(form.cleaned_data["handle"])
            self.identity.also_known_as = aka
        self.identity.save()
        self.identity.transition_perform(IdentityStates.edited)
        return redirect(".")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["identity"] = self.identity
        return context
