from django.db import models
import uuid
from datetime import datetime
from datetime import date
from django.contrib.auth.models import AbstractUser, User
# from .manager import CustomUserManager
# from django.utils.translation import gettext_lazy as _

def get_default_date():
    return date.today() 


def generate_reference_id():
    return str(uuid.uuid4())

user_type_choice =( 
    ("1", "Admin"), 
    ("2", "Manager"), 
    ("3", "Sales"),
    ("4", "Support") 
) 

poc_choice = (
    ("POC", "POC"),
    ("Delivery", "Delivery"),
    ("CR", "CR")
)
status_choice =( 
    ("1", "Active"), 
    ("2", "InActive"),
) 


class CustomUser(AbstractUser):
    role = models.ForeignKey('Roles', on_delete=models.SET_NULL, blank=True, null=True)
    User_Type = models.CharField(max_length=30, choices = user_type_choice)
    Belongs_to =  models.ForeignKey('self', on_delete=models.SET_NULL, blank=True, null=True)
    Status = models.CharField(max_length=30, choices = status_choice, default="1")

 
class Poc_model(models.Model):
    Ref_id = models.CharField(max_length=36, unique=True, default=generate_reference_id)
    Customer_name = models.ForeignKey('Customer', on_delete=models.SET_NULL, blank=True, null=True)
    Product_name = models.ForeignKey('Product', on_delete=models.SET_NULL, blank=True, null=True)
    Requested_date = models.DateField(default=get_default_date)
    Timeline = models.DateField(default=get_default_date)
    status = models.ForeignKey('Status', on_delete=models.SET_NULL, blank=True, null=True)
    added_by = models.ForeignKey('CustomUser', on_delete=models.SET_NULL, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True, blank=True)
    assign_to = models.ForeignKey('CustomUser', on_delete=models.SET_NULL, blank=True, null=True, related_name='assignuser')
    description = models.TextField(default=None, blank=True, null=True)
    poc_type = models.CharField(max_length=30, choices = poc_choice, default="POC")
    kt_given = models.BooleanField(default=False)

class Poc_remark(models.Model):
    poc_id = models.ForeignKey('Poc_model', on_delete=models.CASCADE, blank=True, null=True, related_name='poc_r_related')
    remarks = models.TextField()
    status =  models.TextField(default=None)
    added_by = models.ForeignKey('CustomUser', on_delete=models.SET_NULL, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True, blank=True)


class Product(models.Model):
    Product_name = models.TextField()
    status = models.CharField(max_length=30, choices = status_choice, default="1")
    added_by = models.ForeignKey('CustomUser', on_delete=models.SET_NULL, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True, blank=True)

    def __str__(self):
        return self.Product_name

class Feature(models.Model):
    poc_id = models.ForeignKey('Poc_model', on_delete=models.CASCADE, blank=True, null=True, related_name='poc_f_related')
    features_list = models.TextField()
    status = models.TextField(default=None)
    timeline = models.DateField(default=get_default_date)
    added_by = models.ForeignKey('CustomUser', on_delete=models.SET_NULL, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True, blank=True)


class Feature_status(models.Model):
    feature = models.ForeignKey('Feature', on_delete=models.CASCADE, blank=True, null=True, related_name='feature_related')
    status = models.TextField()
    added_by = models.ForeignKey('CustomUser', on_delete=models.SET_NULL, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True, blank=True)

class Demo_model(models.Model):
    Ref_id = models.CharField(max_length=36, unique=True, default=generate_reference_id)
    Customer_name = models.ForeignKey('Customer', on_delete=models.SET_NULL,  blank=True, null=True)
    Product_name = models.ForeignKey('Product', on_delete=models.SET_NULL, blank=True, null=True)
    Requested_date = models.DateField(default=get_default_date)
    Timeline = models.DateField(default=get_default_date)
    status = models.ForeignKey('Status', on_delete=models.SET_NULL,     blank=True, null=True)
    added_by = models.ForeignKey('CustomUser', on_delete=models.SET_NULL, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True, blank=True)
    assign_to = models.ForeignKey('CustomUser', on_delete=models.SET_NULL, blank=True, null=True, related_name='assignuser_demo')
    description = models.TextField(default=None, blank=True, null=True)
    kt_given = models.BooleanField(default=False)

class Demo_feature(models.Model):
    demo_id = models.ForeignKey('Demo_model', on_delete=models.CASCADE, blank=True, null=True, related_name='demo_f_related')
    features_list = models.TextField()
    status = models.TextField(default=None)
    timeline = models.DateField(default=get_default_date)
    added_by = models.ForeignKey('CustomUser', on_delete=models.SET_NULL, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True, blank=True)


class Demo_Feature_status(models.Model):
    feature = models.ForeignKey('Demo_feature', on_delete=models.CASCADE, blank=True, null=True, related_name='demo_feature_related')
    status = models.TextField()
    added_by = models.ForeignKey('CustomUser', on_delete=models.SET_NULL, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True, blank=True)

class Demo_remark(models.Model):
    demo_id = models.ForeignKey('Demo_model', on_delete=models.CASCADE, blank=True, null=True, related_name='demo_r_related')
    remarks = models.TextField()
    status =  models.TextField(default=None)
    added_by = models.ForeignKey('CustomUser', on_delete=models.SET_NULL, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True, blank=True)



class Roles(models.Model):
    name = models.CharField(max_length=30)
    status = models.CharField(max_length=30, choices = status_choice, default="1")
    # added_by = models.ForeignKey('CustomUser', on_delete=models.SET_NULL, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True, blank=True)
    # role_belongs_to = models.ForeignKey('self', on_delete=models.SET_NULL, blank=True, null=True) 
    def __str__(self):
        return self.name

class Status(models.Model):
    name = models.CharField(max_length=30)
    created_at = models.DateTimeField(auto_now_add=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True, blank=True)

    def __str__(self):
        return self.name

class Customer(models.Model):
    name = models.CharField(max_length=30)
    status = models.CharField(max_length=30, default="Active")
    created_at = models.DateTimeField(auto_now_add=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True, blank=True)

    def __str__(self):
        return self.name


