# Generated by Django 4.1.4 on 2022-12-20 21:11

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0007_remove_invite_email_invite_expires_invite_uses"),
    ]

    operations = [
        migrations.AddField(
            model_name="identity",
            name="also_known_as",
            field=models.JSONField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="identity",
            name="move_to_redirect",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="identity",
            name="moved_to",
            field=models.ForeignKey(
                blank=True,
                null=True,
                limit_choices_to=models.Q(
                    ("actor_type", "person"), ("also_known_as__isnull", False)
                ),
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="moved_from_identities",
                to="users.identity",
            ),
        ),
    ]
