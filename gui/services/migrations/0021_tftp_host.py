# -*- coding: utf-8 -*-
# Generated by Django 1.10.8 on 2019-01-14 11:24
from __future__ import unicode_literals

from django.db import migrations, models
import freenasUI.freeadmin.models.fields


class Migration(migrations.Migration):

    dependencies = [
        ('services', '0020_add_enable_smb1'),
    ]

    operations = [
        migrations.AddField(
            model_name='tftp',
            name='tftp_host',
            field=models.CharField(default='0.0.0.0', max_length=120, verbose_name='Host'),
        ),
    ]
