# Generated by Django 4.0.3 on 2022-04-02 15:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user',
            name='client_id',
        ),
        migrations.AddField(
            model_name='user',
            name='is_sso',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='user',
            name='sso_id',
            field=models.TextField(blank=True, null=True),
        ),
    ]
