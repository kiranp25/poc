from django.shortcuts import render, redirect, HttpResponse
from .models import Users, Product, Roles,Poc_model, Feature, Poc_remark
from django.http import JsonResponse

# Create your views here.



def dahboard(request):
    context = {'name': 'kp'}
    return render(request, 'poc_demo/index.html', context)

# def loginpage(request):

def login(request):
    print("******")
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        request.session['username'] = username
        request.session['password'] = password
        
        error_message = "invalid username"

        print(password, username)

        try:    
            user = Users.objects.get(username=username)
            role = Roles.objects.get(name=user.roles)
            if password == user.password:
                print(password, user.password)
                request.session['roles'] = role.name
                request.session['name'] = user.name
                return redirect('dashboard')
                # elif user.roles == 'Manager':
                #     name = user.name
                #     return redirect('mandash')  
                # elif user.roles == 'Executive':
                #     name = user.name
                #     return redirect('exedash')

            # else:

            #     error_message = "Invalid username or password."
        
        except Users.DoesNotExist:
            return render(request, 'poc_demo/login.html', {'error_message': error_message})
        
    return render(request, 'poc_demo/login.html', {})

def get_data_for(request,usertype):
    flow = {"Admin":'Admin', "Manager": 'Admin', "Sales": 'Manager'}
    user_info = dict()
    # branch_list = cl_Branch.objects.filter(branch_name=request.POST.get('branch_list')).first()
    user_type_id = Roles.objects.get(name=flow[usertype])  
    users  = Users.objects.filter(roles=user_type_id).all()

    type_user_list = [i.name for i in users]
    print(type_user_list, usertype, type(usertype))
    
    user_info = {
        'list_of': type_user_list,    
        }
    return JsonResponse(user_info)


def view_poc(request):
    all_poc = Poc_model.objects.all()
    pass

def add_poc(request):
    all_active_product = Product.objects.all()
    product_list = [product for product in all_active_product]
    if request.method == 'POST':
        try:
            customer_name = request.POST['CustomerName']
            # product_name = request.POST['product_name']
            product_name = Product.objects.get(Product_name=request.POST['product_name'])
            feature_count = request.POST['feature_count']
            features = request.POST.getlist('features')
            Remark_count = request.POST['Remark_count']
            remarks= request.POST.getlist('remarks')
            status= request.POST['status'] 
            added_by = request.POST['username']
            features_list = ",".join(features)
            remarks_list = ",".join(remarks)
            new_poc = Poc_model(Customer_name=customer_name,Product_name=product_name,Features=features_list,Remarks=remarks_list,Status=status,added_by=added_by)
            new_poc.save()
            poc_ref = Poc_model.objects.get(pk=new_poc.id)
            new_feature_list = []
            for feture in features:
                new_feature_list.append({'poc_id': poc_ref, 'features_list':feture, 'status':status})
            new_remarks_list = []
            for remark in remarks:
                new_remarks_list.append({'poc_id': poc_ref, 'remarks': remark, 'status':status})
            # new_fetures = Feature()
            Feature.objects.bulk_create([Feature(**data) for data in new_feature_list])
            # new_remarks = Poc_remark()
            Poc_remark.objects.bulk_create([Poc_remark(**data) for data in new_remarks_list])
            # print(customer_name, product_name, feature_count, features, Remark_count, remarks, status)
        except Exception as e:
            print(e)
        
            
    context = {}
    context['product_list'] = product_list
    return render(request, 'poc_demo/add_poc.html', context)

def add_user(request):
    flow = {"Admin":['Admin', 'Manager', 'Sales'], "Manager": ['Sales'], "Sales": ''}
    user = Users.objects.all()
    roles = Roles.objects.all()
    context = {}
    context['users'] = [i.name for i in user]
    user_type_dict = dict()
    for emp in user:
        if emp.roles not in user_type_dict:
            user_type_dict[emp.roles] = []
        user_type_dict[emp.roles].append(emp.name)
    context['user_list'] = user_type_dict
    context['roles'] = roles
    if request.method == 'POST':
        print(request.POST)
        result = dict()
        try:
            Belongs_to = Users.objects.get(name=request.POST['Belongs_to'])
            usertype = Roles.objects.get(name=request.POST['usertype'])
            user_name = request.POST['name']
            email = request.POST['email']
            username = request.POST['username']
            password = request.POST['password']
            status = request.POST.get('status')
            new_user = Users(name=user_name,email=email,username=username,password=password,belongs_to=Belongs_to,roles=usertype,status=status)
            new_user.save()
            result['message'] = "successfully user added"
        except Exception as e:
            result['message'] = "user not added"
        return redirect('add_users')
    return render(request, 'poc_demo/add_user.html', context)

def add_product(request):
    context = dict()
    
    if request.method == 'POST':
        print(request.POST)
        result = dict()
        try:
            # Belongs_to = Users.objects.get(name=request.POST['Belongs_to'])
            Product_name = request.POST['product_name']
            status = request.POST.get('status')
            new_product = Product(Product_name=Product_name,Status=status,added_by=request.POST['username'])
            new_product.save()
            # request.session['success_message'] = 'Successfully added!'
        except Exception as e:
            # request.session['error_message'] = 'not added!'
            error_message = 'not added'
        return redirect('add_product')
    return render(request, 'poc_demo/add_product.html', context)



def add_role(request):
    context = dict()
    if request.method == 'POST':
        print(request.POST)
        result = dict()
        try:
            # Belongs_to = Users.objects.get(name=request.POST['Belongs_to'])
            Role_name = request.POST['role_name']
            status = request.POST.get('status')
            new_role = Roles(name=Role_name,status=status,added_by=request.POST['username'])
            new_role.save()
            # request.session['success_message'] = 'Successfully added!'
        except Exception as e:
            # request.session['error_message'] = 'not added!'
            error_message = 'not added'
        return redirect('add_role')
    return render(request, 'poc_demo/add_roles.html', context)