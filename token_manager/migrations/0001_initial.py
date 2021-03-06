# Generated by Django 2.2.5 on 2019-10-18 13:25

from django.db import migrations, models
import django_jalali.db.models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='TokenLookUpID',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip', models.CharField(blank=True, max_length=20, null=True)),
                ('os', models.CharField(blank=True, max_length=300, null=True)),
                ('r_type', models.CharField(blank=True, max_length=20, null=True)),
                ('device', models.CharField(blank=True, max_length=20, null=True)),
                ('browser', models.CharField(blank=True, max_length=30, null=True)),
                ('created_at', django_jalali.db.models.jDateTimeField(auto_now_add=True)),
                ('updated_at', django_jalali.db.models.jDateTimeField(auto_now=True)),
            ],
            options={
                'db_table': 'token_manager_lookup_id',
            },
        ),
    ]
