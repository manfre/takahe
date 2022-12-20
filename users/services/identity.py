from typing import cast

from django.db import models
from django.template.defaultfilters import linebreaks_filter

from core.html import strip_html
from users.models import Follow, FollowStates, Identity


class IdentityService:
    """
    High-level helper methods for doing things to identities
    """

    def __init__(self, identity: Identity):
        self.identity = identity

    def following(self) -> models.QuerySet[Identity]:
        return (
            Identity.objects.filter(inbound_follows__source=self.identity)
            .not_deleted()
            .order_by("username")
            .select_related("domain")
        )

    def followers(self) -> models.QuerySet[Identity]:
        return (
            Identity.objects.filter(outbound_follows__target=self.identity)
            .not_deleted()
            .order_by("username")
            .select_related("domain")
        )

    def follow_from(self, from_identity: Identity) -> Follow:
        """
        Follows a user (or does nothing if already followed).
        Returns the follow.
        """
        existing_follow = Follow.maybe_get(from_identity, self.identity)
        if not existing_follow:
            Follow.create_local(from_identity, self.identity)
        elif existing_follow.state not in FollowStates.group_active():
            existing_follow.transition_perform(FollowStates.unrequested)
        return cast(Follow, existing_follow)

    def unfollow_from(self, from_identity: Identity):
        """
        Unfollows a user (or does nothing if not followed).
        """
        existing_follow = Follow.maybe_get(from_identity, self.identity)
        if existing_follow:
            existing_follow.transition_perform(FollowStates.undone)

    def move_local_follows_from(self, from_identity: Identity):
        """
        Move all of the (local -> local) Follows from from_identity.
        """
        from_local_follows = Follow.objects.select_related(
            "source",
            "source__domain",
            "target",
            "target__domain",
        ).filter(
            models.Q(source=from_identity, source__local=True)
            | models.Q(target=from_identity, target__local=True),
        )
        existing_target_follows = Follow.objects.filter(
            models.Q(source=self.identity, source__local=True)
            | models.Q(target=self.identity, target__local=True),
        )
        existing_targets = {x.target_id for x in existing_target_follows}
        existing_sources = {x.source_id for x in existing_target_follows}

        dupes = []

        for follow in from_local_follows:
            # Following other
            if follow.source == from_identity:
                if self.identity.id in existing_sources:
                    dupes.append(follow)
                else:
                    follow.source = self.identity
                    follow.uri = self.identity.actor_uri + f"follow/{follow.pk}/"
            # Followd by other
            elif follow.target == from_identity:
                if self.identity.id in existing_targets:
                    dupes.append(follow)
                else:
                    follow.target = self.identity

        # In-place move the follow record to the self identity
        Follow.objects.bulk_update(
            from_local_follows, fields=["source", "uri", "target"], batch_size=1000
        )

        # Remove the follows from the from_identity that the target already had
        Follow.objects.filter(pk__in=[x.id for x in dupes]).delete()

    def mastodon_json_relationship(self, from_identity: Identity):
        """
        Returns a Relationship object for the from_identity's relationship
        with this identity.
        """
        return {
            "id": self.identity.pk,
            "following": self.identity.inbound_follows.filter(
                source=from_identity,
                state__in=FollowStates.group_active(),
            ).exists(),
            "followed_by": self.identity.outbound_follows.filter(
                target=from_identity,
                state__in=FollowStates.group_active(),
            ).exists(),
            "showing_reblogs": True,
            "notifying": False,
            "blocking": False,
            "blocked_by": False,
            "muting": False,
            "muting_notifications": False,
            "requested": False,
            "domain_blocking": False,
            "endorsed": False,
            "note": "",
        }

    def set_summary(self, summary: str):
        """
        Safely sets a summary and turns linebreaks into HTML
        """
        if summary:
            self.identity.summary = linebreaks_filter(strip_html(summary))
        else:
            self.identity.summary = None
        self.identity.save()
