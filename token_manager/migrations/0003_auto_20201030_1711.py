# Generated by Django 2.2.5 on 2020-10-30 17:11

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('token_manager', '0002_tokenlookupid_user'),
    ]

    operations = [
        migrations.AlterField(
            model_name='tokenlookupid',
            name='browser',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='tokenlookupid',
            name='device',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='tokenlookupid',
            name='ip',
            field=models.CharField(blank=True, max_length=30, null=True),
        ),
        migrations.AlterField(
            model_name='tokenlookupid',
            name='r_type',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
    ]