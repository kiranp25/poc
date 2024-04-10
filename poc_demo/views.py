from django.shortcuts import render, redirect, HttpResponse,get_object_or_404
from .models import Product, Roles,Poc_model, Feature, Poc_remark, Status, Feature_status, status_choice,  user_type_choice, CustomUser
from django.http import JsonResponse
from django.core.paginator import Paginator
from django.db.models import Q
from django.contrib import messages
from django.contrib.auth import authenticate, login,logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.db.models import Prefetch

# Create your views here.
User = get_user_model()

@login_required(login_url='loginpage')
def dahboard(request):
    context = {'name': 'kp'}
    return render(request, 'poc_demo/index.html', context)

# def loginpage(request):


def login_page(request):
    print("******")
    try:
        if request.method == 'POST':
            email = request.POST['email']
            password = request.POST['password']

            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                messages.error(request,'user not exist', extra_tags="danger")
                return redirect('loginpage')
            
            if user:
                user = authenticate(username=user.username, password=password)
                if user is None:
                    messages.warning(request, 'invalid password')
                    return redirect('loginpage')
                else:
                    login(request, user)
                    return redirect('dashboard')
    except Exception as e:
        print(e)
    return render(request, 'poc_demo/login.html', {})


def logout_page(request):
    logout(request)
    return redirect('loginpage')

@login_required(login_url='loginpage')
def get_data_for(request,usertype):
    flow = {"Admin":'Admin', "Manager": 'Admin', "Sales": 'Manager', 'Support': 'Manager'}
    user_info = dict()
    # branch_list = cl_Branch.objects.filter(branch_name=request.POST.get('branch_list')).first()
    # needs to change with role_belongs_to from Roles models.
    print(usertype)
    user_type_id = Roles.objects.get(name=flow[usertype])  

    print(user_type_id)
    users  = User.objects.filter(role=user_type_id).all()

    print(users)
    user_dict = dict()
    for data in users:
        if data.id not in user_dict:
            user_dict[data.id] = data.username

    # type_user_list = [i.first_name + " " +i.last_name for i in users]
    # print(type_user_list, usertype, type(usertype))
    
    user_info = {
        'list_of': user_dict,    
        }
    return JsonResponse(user_info)

@login_required(login_url='loginpage')
def view_poc(request):
    all_poc = Poc_model.objects.all()
    pass

@login_required(login_url='loginpage')
def add_poc(request):
    all_active_product = Product.objects.all()
    sts = Status.objects.all()
    context = {}
    context['status'] = sts
    product_list = [product for product in all_active_product]
    
    if request.method == 'POST':
        try:
            print(request.POST)
            customer_name = request.POST['CustomerName']
            # product_name = request.POST['product_name']
            product_name = Product.objects.get(Product_name=request.POST['product_name'])
            feature_count = request.POST['feature_count']
            features_list = request.POST.getlist('Feature_ids')
            features = request.POST.getlist('features')
            Remark_count = request.POST['Remark_count']
            remarks= request.POST.getlist('remarks')
            # status= request.POST['status'] 
            status = Status.objects.get(name=request.POST['status'])
            added_by = CustomUser.objects.get(id=request.user.id)
            Timeline = request.POST['timeline']
            # features_list = ",".join(features)
            remarks_list = ",".join(remarks)

            new_poc = Poc_model(Customer_name=customer_name,Product_name=product_name,status=status,added_by=added_by,Timeline=Timeline)
            new_poc.save()

            poc_ref = Poc_model.objects.get(pk=new_poc.id)
            
            new_feature_list = []
            for feture in features:
                new_feature_list.append({'poc_id': poc_ref, 'features_list':feture, 'status':status, 'added_by': added_by})            
            messages.success(request, "poc added successfully")
            new_feature_list = []
            for j in features_list:
                print(request.POST[f'features_{j}'])
                print(request.POST[f'timeline_{j}'])
                new_feature_list.append({'poc_id': poc_ref, 'features_list':request.POST[f'features_{j}'],'timeline':request.POST[f'timeline_{j}'], 'status':status, 'added_by': added_by}) 
            # Access created features and their status objects:
            features_lsts_added = []
            for data in new_feature_list:
                feature = Feature.objects.create(**data)  # Create the Feature object
                status_data = Feature_status.objects.create(feature=feature, status=status, added_by=added_by)  # Create the Status object linked to the Feature
                features_lsts_added.append(status_data)
            messages.success(request, "poc added successfully")
            new_remarks_list = []
            for remark in remarks:
                new_remarks_list.append({'poc_id': poc_ref, 'remarks': remark, 'status':status, 'added_by': added_by})
            # new_fetures = Feature()
            # Feature.objects.bulk_create([Feature(**data) for data in new_feature_list])
            # new_remarks = Poc_remark()
            Poc_remark.objects.bulk_create([Poc_remark(**data) for data in new_remarks_list])
        except Exception as e:
            print(e)
            messages.error(request,f"poc not added {e}")
        
    context['product_list'] = product_list
    return render(request, 'poc_demo/add_poc.html', context)


@login_required(login_url='loginpage')
def add_user(request):
    flow = {"Admin":['Admin', 'Manager', 'Sales'], "Manager": ['Sales'], "Sales": ''}
    user = User.objects.all()
    roles = Roles.objects.all()
    for i in roles:
        print(i)
    sts = status_choice
    print(sts)
    context = {}
    context['users'] = [i.first_name for i in user]
    user_type_dict = dict()
    for emp in user:
        print("************")
        print(emp.User_Type)
        if emp.User_Type not in user_type_dict:
            user_type_dict[emp.User_Type] = []
        user_type_dict[emp.User_Type].append(emp.first_name)
    context['user_list'] = user_type_dict
    context['roles'] = roles
    context['status'] = sts
    if request.method == 'POST':
        print(request.POST)
        result = dict()
        try:
            existing_user = User.objects.filter(email=request.POST['email']).first()

            if existing_user:
                messages.error(request, 'Email address already in use. Please choose a different one.')
            else:
                Belongs_to = User.objects.get(id=request.POST['Belongs_to'])
                usertype = Roles.objects.get(name=request.POST['usertype'])
                first_name = request.POST['first_name']
                last_name = request.POST['last_name']
                email = request.POST['email']
                username = request.POST['username']
                password = request.POST['password']
                status = request.POST.get('status')
                
                new_user = User.objects.create(first_name=first_name,last_name=last_name,email=email,username=username,Belongs_to=Belongs_to,role=usertype,Status=status)
                new_user.set_password(password)
                new_user.save()
                # result['message'] = "successfully user added"
                messages.success(request,'successfully user added')
        except Exception as e:
            messages.success(request,f'user  not added {e}')
        return redirect('add_users')
    return render(request, 'poc_demo/add_user.html', context)


@login_required(login_url='loginpage')
def view_users(request):
    user = User.objects.all()
    if request.method == 'POST':
        pass
    context = {
        "users":user,
        "status":status_choice
    }

    return render(request, 'poc_demo/user_view.html', context)

@login_required(login_url='loginpage')
def edit_user(request, id):
    user = get_object_or_404(User, pk=id)  # Fetch user by ID
    flow = {"Admin":['Admin', 'Manager', 'Sales'], "Manager": ['Sales'], "Sales": ''}
    roles = Roles.objects.all()
    for i in roles:
        print(i)
    sts = status_choice
    print(sts)
    context = {}
    user_type_dict = dict()
    
    if request.method == 'POST':
        print(request.POST)
        try:
            existing_user = User.objects.filter(email=request.POST['email']).exclude(pk=user.id).first()

            if existing_user:
                messages.error(request, 'Email address already in use. Please choose a different one.')
            else:
                user.first_name = request.POST['first_name']
                user.last_name = request.POST['last_name']
                user.email = request.POST['email']
                user.Belongs_to = User.objects.get(id=request.POST['Belongs_to'])
                user.role = Roles.objects.get(name=request.POST['usertype'])
                user.Status = request.POST.get('status')
                user.save()
                messages.success(request,'successfully user updaed')
        except Exception as e:
            messages.error(request,f'user not updated {e}')
            return redirect('add_users')
    context = {'user': user,
               'roles': roles,
               'status': sts
               }
    return render(request, 'poc_demo/edit_user.html', context)


@login_required(login_url='loginpage')
def add_product(request):
    context = dict()
    sts = status_choice
    context['status'] = sts
    if request.method == 'POST':
        print(request.POST)
        result = dict()
        try:
            # Belongs_to = Users.objects.get(name=request.POST['Belongs_to'])
            Product_name = request.POST['product_name']
            status = request.POST.get('status') #request.POST.get('status')
            new_product = Product(Product_name=Product_name,status=status,added_by=CustomUser.objects.get(id=request.user.id))
            new_product.save()
            messages.success(request, "product added successfully")
            # request.session['success_message'] = 'Successfully added!'
        except Exception as e:
            print(e)
            messages.success(request, f"product not added {e}")
            # request.session['error_message'] = 'not added!'
            error_message = 'not added'
        return redirect('add_product')
    return render(request, 'poc_demo/add_product.html', context)

def view_product(request):
    product = Product.objects.all()
    context = {
        "products" : product,
        "status" : status_choice
    }
    return render(request, 'poc_demo/view_products.html', context)



@login_required(login_url='loginpage')
def add_role(request):
    context = dict()
    sts = status_choice
    context['status'] = sts
    if request.method == 'POST':
        print(request.POST)
        result = dict()
        try:
            # if check Roles available and then create
            # Belongs_to = Users.objects.get(name=request.POST['Belongs_to'])  
            Role_name = request.POST['role_name']
            status = request.POST.get('status') #request.POST.get('status')
            print(status)
            new_role = Roles(name=Role_name,status=status,added_by=CustomUser.objects.get(id=request.user.id))
            new_role.save()
            messages.success(request, f"Role added Successfully")
            # request.session['success_message'] = 'Successfully added!'
        except Exception as e:
            # request.session['error_message'] = 'not added!'
            messages.error(request, f"Role Not Added {e}")
        return redirect('add_role')
    return render(request, 'poc_demo/add_roles.html', context)


@login_required(login_url='loginpage')
def view_roles(request):
    roles = Roles.objects.all()
    if request.method == 'POST':
        pass
    context = {
        "roles":roles,
        "status":status_choice
    }
    return render(request, 'poc_demo/view_roles.html', context)


@login_required(login_url='loginpage')
def edit_role(request, id):
    try:
        role = get_object_or_404(Roles, pk=id)
        if request.method == "POST":
            print(request.POST) 
            role.name = request.POST['role_name']
            role.status = request.POST.get('status')
            role.save()
            messages.success(request, 'Role Updated')
    except Exception as e:
        messages.error(request,f"Role Not Updated {e}")
    context = {'role': role,
               'status':status_choice
            }
    return render(request, 'poc_demo/edit_role.html', context)


@login_required(login_url='loginpage')
def add_status(request):
    context = dict()
    if request.method == 'POST':
        print(request.POST)
        result = dict()
        try:
            # Belongs_to = Users.objects.get(name=request.POST['Belongs_to'])
            sts = request.POST['status_name']
            if Status.objects.filter(name=sts).count() > 0:
                messages.error(request, f'{sts} status alredy exist')
            else:
                Status.objects.create(name=sts,added_by=CustomUser.objects.get(id=request.user.id))       
                messages.success(request, f"Status added Successfully")

            return redirect('add_status')
            
            # request.session['success_message'] = 'Successfully added!'
        except Exception as e:
            # request.session['error_message'] = 'not added!'
            error_message = 'not added'
            messages.success(request, f"Status not added {e}")
            print(e)
        return redirect('add_status')
    return render(request, 'poc_demo/add_status.html', context)


@login_required(login_url='loginpage')
def view_status(request):
    new_sts = Status.objects.all()
    if request.method == 'POST':
        pass
    context = {
        "status":new_sts
    }
    return render(request, 'poc_demo/status_view.html', context)


@login_required(login_url='loginpage')
def edit_status(request, id):
    try:
        status = get_object_or_404(Status, pk=id)
        if request.method == "POST":
            print(request.POST)
            if Status.objects.filter(name=request.POST['status_name']).exclude(pk=id).first():
                messages.error(request, f"{request.POST['status_name']} status alredy exist")
                return redirect('edit_status')
            status.name = request.POST['status_name']
            status.save()
            messages.success(request, 'status updated')
    except Exception as e:
        messages.error(request,"status not updated")
    context = {'status': status,}
    return render(request, 'poc_demo/edit_status.html', context)


@login_required(login_url='loginpage')
def edit_product(request, id):
    try:
        product = get_object_or_404(Product, pk=id)
        if request.method == "POST":
            print(request.POST)
            product.Product_name = request.POST['product_name']
            product.status = request.POST.get('status') #request.POST.get('status')
            product.save()
            messages.success(request, 'product updated')
    except Exception as e:
        messages.error(request,f"product not updated {e}")
    context = {
                'product': product,
               'status': status_choice
            }
    return render(request, 'poc_demo/edit_product.html', context)


@login_required(login_url='loginpage')
def view_poc(request):
    print(request.user.role)
    if request.user.role_id == 1:
        all_active_product = Poc_model.objects.prefetch_related('poc_f_related', 'poc_r_related').all() 
    elif request.user.role_id == 3:
        all_active_product = Poc_model.objects.filter(added_by__Belongs_to=request.user.id).prefetch_related('poc_f_related', 'poc_r_related').all() 
    elif request.user.role_id == 2:
        all_active_product = Poc_model.objects.filter(added_by=request.user.id).prefetch_related('poc_f_related', 'poc_r_related').all() 
    elif request.user.role_id == 4:
        all_active_product = Poc_model.objects.filter(assign_to=request.user.id).prefetch_related('poc_f_related', 'poc_r_related').all()
    search_query = request.GET.get('search', '')

    if search_query:
        if search_query:
            all_active_product = all_active_product.filter(
            Q(Customer_name__icontains=search_query) |
            Q(Requested_date__icontains=search_query) |
            Q(Timeline__icontains=search_query) |
            Q(added_by__icontains=search_query)
        )
    paginator = Paginator(all_active_product, 10)
    page_number = request.GET.get('page')
    page = paginator.get_page(page_number)    
    context = {'paginator': paginator, 'page': page}
    context["data"] = all_active_product   
    context['search_query'] = search_query              
    
    return render(request, 'poc_demo/view_poc.html', context)


def add_remarks(request, id):
    try:
        if request.method == 'POST':
            Remark_count = request.POST['Remark_count']
            remarks= request.POST.getlist('remarks')
            added_by = CustomUser.objects.get(id=request.user.id)
            rid = request.POST['row_remark_id']
            # status= request.POST['status'] 
            get_poc = Poc_model.objects.get(pk=rid)
            # get_poc.Remarks += remarks_list
            # get_poc.Remarks = ",".join(get_poc.Remarks.split(',') + remarks)
            # # print(remarks_list)
            # get_poc.save()
            new_remarks_list = []
            for remark in remarks:
                new_remarks_list.append({'poc_id': get_poc, 'remarks': remark, 'status':get_poc.status, 'added_by': added_by})
            # new_remarks = Poc_remark()
            Poc_remark.objects.bulk_create([Poc_remark(**data) for data in new_remarks_list])
            return redirect('view_poc_detail', id=id)
    except Exception as e:
        print(e)
        return redirect('view_poc_detail', id=id)


@login_required(login_url='loginpage')
def edit_poc(request, id):
    try:
        if request.method == 'POST':
            print(request.POST)
            get_poc = Poc_model.objects.get(pk=id)
            product_name = Product.objects.get(Product_name=request.POST['product_name'])    
            status = Status.objects.get(name=request.POST['status'])
            get_poc.Customer_name = request.POST['Customer_name']
            get_poc.Product_name = product_name
            get_poc.Timeline = request.POST['Timeline_date']
            get_poc.status = status
            get_poc.assign_to = User.objects.get(pk=request.POST['assign_edit'])
            get_poc.save()
            messages.success(request, 'poc updated')
    except Exception as e:
        messages.error(request, f"poc not edted {e}")
    return redirect('view_poc_detail', id=id)


@login_required(login_url='loginpage')
def update_sts(request):
    if request.method == 'POST':
        try:
            print("###########")
            print(request.POST)
            sts_id = request.POST['sts_id']
            status = request.POST['status']
            poc_id = request.POST['poc_id']
            added_by = CustomUser.objects.get(id=request.user.id)
            print(added_by,'$$$$')
            featureobj = Feature.objects.get(pk=sts_id)
            Feature_status.objects.create(feature=featureobj,status=status,added_by=added_by)
            messages.success(request, "status updated")
            # return redirect('view_poc_detail', id=id)
            return HttpResponse('<div class="messages text-center alert alert-success"> <h2> status submitted.</h2> </div>') #just for testing purpose you can remove it.
        except Exception as e:
            return HttpResponse(f'<div class="messages text-center alert alert-danger"> <h2> status not added {e}.</h2> </div>') 


@login_required(login_url='loginpage')
def view_poc_detail(request, id):
    poc = Poc_model.objects.prefetch_related('poc_f_related', 'poc_r_related').get(id=id)
    html_feture_only = ''' '''
    html_feture_sts_only = ''' '''
    html = ''' '''
    for feature in poc.poc_f_related.all():       
        elated_objects_count = feature.feature_related.count() + 1
        row_class = ''  # Initialize row class
        if elated_objects_count > 5:
            row_class = 'scrollable-row'  # Add class for scrolling if needed
        html_feture_only += f'''
                    <tr>
                     <td>{feature.features_list }</td>
                    <td>{ feature.timeline }</td>
                    <td>{ feature.status }</td>
                    <td>
                    <button class="btn btn-sm btn-primary" id="fet_{ feature.id }" value="{ feature.id }" onclick="view_sts_feature(this)"> View Status
                          </button>
                      <button class="btn btn-sm btn-primary" data-bs-toggle="modal" value="{feature.id}" onclick="update_sts(this)" data-bs-target="#centeredModalupdate">
                      Add Status
                    </button></td>
                    </tr>'''
        html += f'''
        <tr>
            <td rowspan="{elated_objects_count}">{ feature.features_list }</td>
                    <td rowspan="{elated_objects_count}">{ feature.timeline }</td>
                    <td rowspan="{elated_objects_count}">{ feature.status }</td>
                    <td rowspan="{elated_objects_count}">
                      <button class="btn btn-sm btn-primary" data-bs-toggle="modal" value="{feature.id}" onclick="update_sts(this)" data-bs-target="#centeredModalupdate">
                      Add Status
                    </button></td>
                    </tr>'''
        for data in feature.feature_related.all().order_by('-created_at'):
            html += f'''
                    <tr>
                    <td>{ data.status }</td>
                      <td>{ data.added_by }</td>
                      <td>{ data.created_at }</td>
                      </tr>'''
            html_feture_sts_only += f'''
                    <tr>
                     <td>{ feature.features_list }</td>
                    <td>{ data.status }</td>
                      <td>{ data.added_by }</td>
                      <td>{ data.created_at }</td>
                      </tr>''' 
    all_active_product = Product.objects.all()
    status_list = Status.objects.all()
    assign_to = User.objects.filter(role=4)

    print(assign_to)
    permition = [1,2,3]
    if request.method == 'POST':
        try:
            Remark_count = request.POST['Remark_count']
            remarks= request.POST.getlist('remarks')
            # status= request.POST['status'] 
            added_by = CustomUser.objects.get(id=request.user.id)
            rid = request.POST['row_remark_id']
            get_poc = Poc_model.objects.get(pk=rid)
            # get_poc.Remarks += remarks_list
            # get_poc.Remarks = ",".join(get_poc.Remarks.split(',') + remarks)
            # # print(remarks_list)
            # get_poc.save()
            new_remarks_list = []
            for remark in remarks:
                new_remarks_list.append({'poc_id': get_poc, 'remarks': remark, 'status':get_poc.status, 'added_by': added_by})
            # new_remarks = Poc_remark()
            Poc_remark.objects.bulk_create([Poc_remark(**data) for data in new_remarks_list])
            return redirect('view_poc_detail', id=id)
        except Exception as e:
            print(e)
    return render(request, 'poc_demo/view_poc_detail.html', {'data': poc, 'status': status_list, 'html': html, 'product': all_active_product, 'permition': [1,2,3], "assign_to": assign_to, "html_feture_sts_only":html_feture_sts_only, "html_feture_only":html_feture_only })


@login_required(login_url='loginpage')
def get_detail_sts(request):
    sts_data = dict()
    if request.method == 'POST':
        id = request.POST.get('id')
        feature = Feature.objects.get(pk=id)
        get_data = Feature_status.objects.filter(feature=feature).order_by('-created_at')
        
        for data in get_data:
            print(data.id)
            sts_data[f'new_{data.id}'] = {'status': data.status, 'added_by': data.added_by.username, 'time': data.created_at, 'feature': feature.features_list}
        print(sts_data)
    # branch_list = cl_Branch.objects.filter(branch_name=request.POST.get('branch_list')).first()
    # user_type_id = Roles.objects.get(name=flow[usertype])  
    # users  = Users.objects.filter(roles=user_type_id).all()
    # type_user_list = [i.name for i in users]
    # print(type_user_list, usertype, type(usertype))
    
    return JsonResponse(sts_data)


@login_required(login_url='loginpage')
def delete_role(request, id):
    try:
        Roles.objects.get(pk=id).delete()
        messages.success(request,'deleted')
        pass
    except Exception as e:
        messages.error(request,f'not deleted {e}', extra_tags='danger')
    return redirect('view_roles')


@login_required(login_url='loginpage')
def delete_product(request, id):
    try:
        Product.objects.get(pk=id).delete()
        messages.success(request,'deleted')
    except Exception as e:
        messages.error(request,f'not deleted {e}', extra_tags='danger')
    return redirect('view_product')


@login_required(login_url='loginpage')
def delete_user(request, id):
    try:
        User.objects.get(pk=id).delete()
        messages.success(request,'deleted')
    except Exception as e:
        messages.error(request,f'not deleted {e}', extra_tags='danger')
    return redirect('view_users')


@login_required(login_url='loginpage')
def delete_status(request, id):
    try:
        Status.objects.get(pk=id).delete()
        messages.success(request,'deleted')
    except Exception as e:
        messages.error(request,f'not deleted {e}', extra_tags='danger')
    return redirect('view_status')
    