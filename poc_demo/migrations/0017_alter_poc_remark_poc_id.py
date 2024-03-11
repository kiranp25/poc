# Generated by Django 5.0.2 on 2024-03-08 05:50

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('poc_demo', '0016_remove_demo_model_features_remove_demo_model_remarks_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='poc_remark',
            name='poc_id',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='remarks', to='poc_demo.poc_model'),
        ),
    ]
