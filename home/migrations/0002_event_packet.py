# Generated by Django 4.2.11 on 2024-04-19 21:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Event',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('message', models.TextField()),
            ],
        ),
        migrations.CreateModel(
            name='Packet',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('source_ip', models.CharField(max_length=50)),
                ('destination_ip', models.CharField(max_length=50)),
                ('protocol', models.CharField(max_length=10)),
                ('payload', models.TextField()),
            ],
        ),
    ]