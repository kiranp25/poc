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
    Customer_name = models.CharField(max_length=30)
    Product_name = models.ForeignKey('Product', on_delete=models.SET_NULL, blank=True, null=True)
    Requested_date = models.DateField(default=get_default_date)
    Timeline = models.DateField(default=get_default_date)
    status = models.ForeignKey('Status', on_delete=models.SET_NULL,     blank=True, null=True)
    added_by = models.ForeignKey('CustomUser', on_delete=models.SET_NULL, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True, blank=True)
    

class Demo_model(models.Model):
    Ref_id = models.CharField(max_length=36, unique=True, default=generate_reference_id)
    Customer_name = models.CharField(max_length=30)
    Product_name = models.ForeignKey('Product', on_delete=models.SET_NULL, blank=True, null=True)
    # Features = models.TextField()
    Requested_date = models.DateField(default=get_default_date)
    # Remarks = models.TextField()
    Timeline = models.DateField(default=get_default_date)
    status = models.ForeignKey('Status', on_delete=models.SET_NULL, blank=True, null=True)
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
    poc_id = models.ForeignKey('Poc_model', on_delete=models.CASCADE, blank=True, null=True)
    features_list = models.TextField()
    status = models.TextField(default=None)
    timeline = models.DateField(default=get_default_date)
    added_by = models.ForeignKey('CustomUser', on_delete=models.SET_NULL, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True, blank=True)


class Feature_status(models.Model):
    feature = models.ForeignKey('Feature', on_delete=models.CASCADE, blank=True, null=True)
    status = models.TextField()
    added_by = models.ForeignKey('CustomUser', on_delete=models.SET_NULL, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True, blank=True)


class Demo_feature(models.Model):
    Demo_id = models.ForeignKey('Poc_model', on_delete=models.CASCADE, blank=True, null=True)
    Features_list = models.TextField()
    status = models.TextField(default=None)
    added_by = models.ForeignKey('CustomUser', on_delete=models.SET_NULL, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True, blank=True)


class Poc_remark(models.Model):
    poc_id = models.ForeignKey('Poc_model', on_delete=models.CASCADE, blank=True, null=True)
    remarks = models.TextField()
    status =  models.TextField(default=None)
    added_by = added_by = models.ForeignKey('CustomUser', on_delete=models.SET_NULL, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True, blank=True)


class Demo_remark(models.Model):
    Demo_id = models.ForeignKey('Poc_model', on_delete=models.CASCADE, blank=True, null=True)
    Remarks = models.TextField()
    status =  models.TextField(default=None)
    added_by = models.ForeignKey('CustomUser', on_delete=models.SET_NULL, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True, blank=True)


class Roles(models.Model):
    name = models.CharField(max_length=30)
    status = models.CharField(max_length=30, choices = status_choice, default="1")
    added_by = models.ForeignKey('CustomUser', on_delete=models.SET_NULL, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True, blank=True)
    # role_belongs_to = models.ForeignKey('self', on_delete=models.SET_NULL, blank=True, null=True) 
    def __str__(self):
        return self.name

class Status(models.Model):
    name = models.CharField(max_length=30)
    added_by = models.ForeignKey('CustomUser', on_delete=models.SET_NULL, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True, blank=True)

    def __str__(self):
        return self.name