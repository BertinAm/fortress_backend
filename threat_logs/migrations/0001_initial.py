# Generated by Django 5.2.3 on 2025-06-27 01:44

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='ThreatLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('type', models.CharField(choices=[('XSS', 'Cross Site Scripting'), ('BruteForce', 'Brute Force Attack'), ('Other', 'Other')], max_length=50)),
                ('source_ip', models.GenericIPAddressField()),
                ('description', models.TextField()),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
            ],
        ),
    ]
