# Generated by Django 5.0.2 on 2024-03-06 10:11

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('poc_demo', '0007_poc_model_added_by'),
    ]

    operations = [
        migrations.AlterField(
            model_name='demo_model',
            name='Features',
            field=models.TextField(),
        ),
        migrations.AlterField(
            model_name='demo_model',
            name='Remarks',
            field=models.TextField(),
        ),
        migrations.AlterField(
            model_name='poc_model',
            name='Features',
            field=models.TextField(),
        ),
        migrations.AlterField(
            model_name='poc_model',
            name='Remarks',
            field=models.TextField(),
        ),
    ]
