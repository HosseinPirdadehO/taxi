# Generated by Django 5.2.4 on 2025-07-23 15:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0009_alter_schoolprofile_school_location_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='parentprofile',
            name='students',
            field=models.ManyToManyField(blank=True, related_name='parents', to='users.studentprofile', verbose_name='دانش\u200cآموزان مرتبط'),
        ),
    ]
