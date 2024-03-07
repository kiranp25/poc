from django.db import models
import uuid

def generate_reference_id():
    return str(uuid.uuid4())

user_type_choice =( 
    ("1", "Admin"), 
    ("2", "Manager"), 
    ("3", "sales") 
) 

status_choice =( 
    ("1", "Active"), 
    ("2", "inActive"), 
    ("3", "closed") 
) 
  
# class User(models.Model):
#     username = models.CharField(max_length=30)
#     password = models.CharField(max_length=30)
#     logged_in = models.DateTimeField(auto_now_add=True)
#     First_name = models.CharField(max_length=30)
#     Last_name = models.CharField(max_length=30)
#     User_Type = models.CharField(max_length=30, choices = user_type_choice)
#     Email_id = models.CharField(max_length=30)
#     Belongs_to =  models.ForeignKey('self', on_delete=models.SET_NULL, blank=True, null=True)
#     Status = models.CharField(max_length=30, choices = status_choice)

#     def __str__(self):
#         return self.First_name + " " + self.Last_name

class Users(models.Model):
    name = models.CharField(max_length=100)
    username = models.CharField(max_length=100)
    email = models.EmailField(default="abc@olatechs.com")
    password = models.CharField(max_length=100)
    roles   = models.ForeignKey('Roles', on_delete=models.SET_NULL, blank=True, null=True)
    belongs_to =  models.ForeignKey('self', on_delete=models.SET_NULL, blank=True, null=True)
    status = models.ForeignKey('Status', on_delete=models.SET_NULL, blank=True, null=True)
    logged_in = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.username
    
class Poc_model(models.Model):
    Ref_id = models.CharField(max_length=36, unique=True, default=generate_reference_id)
    Customer_name = models.CharField(max_length=30)
    Product_name = models.ForeignKey('Product', on_delete=models.SET_NULL, blank=True, null=True)
    Features =  models.TextField()
    Requested_date = models.DateTimeField(auto_now=True)
    Remarks = models.TextField()
    Timeline = models.DateTimeField(auto_now=True)
    status = models.ForeignKey('Status', on_delete=models.SET_NULL, blank=True, null=True)
    added_by = models.CharField(max_length=30, default='None')
    

class Demo_model(models.Model):
    Ref_id = models.CharField(max_length=36, unique=True, default=generate_reference_id)
    Customer_name = models.CharField(max_length=30)
    Product_name = models.ForeignKey('Product', on_delete=models.SET_NULL, blank=True, null=True)
    Features = models.TextField()
    Requested_date = models.DateTimeField(auto_now=True)
    Remarks = models.TextField()
    Timeline = models.DateTimeField(auto_now=True)
    status = models.ForeignKey('Status', on_delete=models.SET_NULL, blank=True, null=True)

class Product(models.Model):
    Product_name = models.TextField()
    Created_date = models.DateTimeField(auto_now=True)
    status = models.ForeignKey('Status', on_delete=models.SET_NULL, blank=True, null=True)
    added_by = models.CharField(max_length=30, default='None')

    def __str__(self):
        return self.Product_name

class Feature(models.Model):
    poc_id = models.ForeignKey('Poc_model', on_delete=models.CASCADE, blank=True, null=True)
    features_list = models.TextField()
    status = models.ForeignKey('Status', on_delete=models.SET_NULL, blank=True, null=True)


class Demo_feature(models.Model):
    Demo_id = models.ForeignKey('Poc_model', on_delete=models.CASCADE, blank=True, null=True)
    Features_list = models.TextField()
    status = models.ForeignKey('Status', on_delete=models.SET_NULL, blank=True, null=True)


class Poc_remark(models.Model):
    poc_id = models.ForeignKey('Poc_model', on_delete=models.CASCADE, blank=True, null=True)
    remarks = models.TextField()
    status =  models.ForeignKey('Status', on_delete=models.SET_NULL, blank=True, null=True)


class Demo_remark(models.Model):
    Demo_id = models.ForeignKey('Poc_model', on_delete=models.CASCADE, blank=True, null=True)
    Remarks = models.TextField()
    status =  models.ForeignKey('Status', on_delete=models.SET_NULL, blank=True, null=True)


class Roles(models.Model):
    name = models.CharField(max_length=30)
    status = models.ForeignKey('Status', on_delete=models.SET_NULL, blank=True, null=True)
    added_by = models.CharField(max_length=30)
    def __str__(self):
        return self.name

class Status(models.Model):
    name = models.CharField(max_length=30)
    added_by = models.CharField(max_length=30)
    def __str__(self):
        return self.name