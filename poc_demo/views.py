from django.shortcuts import render, redirect, HttpResponse, get_object_or_404
from .models import *
from django.http import JsonResponse
from django.core.paginator import Paginator
from django.db.models import Q
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.db.models import Prefetch
from django.contrib.auth.models import User, Permission, Group
from django.contrib.contenttypes.models import ContentType

# Create your views here.
User = get_user_model()


@login_required(login_url='loginpage')
def dahboard(request):
    user_types = request.user.role
    all_active_product = Product.objects.all()
    all_poc = Poc_model.objects.all()
    all_users = User.objects.all()
    all_demo = Demo_model.objects.all()
    context = {'name': 'kp', 'user_type': user_types, 'Products': all_active_product, "poc": all_poc, "demo": all_demo,
               "user": all_users}
    return render(request, 'poc_demo/index.html', context)


# def loginpage(request):


def login_page(request):
    try:
        if request.method == 'POST':
            email = request.POST['email']
            password = request.POST['password']

            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                messages.error(request, 'User dose not exist.', extra_tags="danger")
                return redirect('loginpage')

            if user:
                user = authenticate(username=user.username, password=password)
                if user is None:
                    messages.warning(request, 'invalid password.')
                    return redirect('loginpage')
                else:
                    login(request, user)

                    content_type = ContentType.objects.get_for_model(Poc_model)
                    post_permission = Permission.objects.filter(content_type=content_type)
                    # print([perm.codename for perm in post_permission])
                    return redirect('dashboard')
    except Exception as e:
        print(e)
    return render(request, 'poc_demo/login.html', {})


def logout_page(request):
    logout(request)
    return redirect('loginpage')


@login_required(login_url='loginpage')
def get_data_for(request, usertype):
    flow = {"Admin": 'Admin', "Manager": 'Admin', "Sales": 'Manager', 'Support': 'Manager'}
    user_info = dict()
    # branch_list = cl_Branch.objects.filter(branch_name=request.POST.get('branch_list')).first()
    # needs to change with role_belongs_to from Roles models.
    user_type_id = Roles.objects.get(name=flow[usertype])
    users = User.objects.filter(role=user_type_id).all()
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
            product_name = Product.objects.get(Product_name=request.POST['product_name'])
            # existing_poc = Poc_model.objects.filter(Product_name=product_name).first()
            # if existing_poc:
            #     messages.error(request, 'Poc already exist for same product.',
            #                    extra_tags="danger")
            if not True:
                pass
            else:
                customer_name = request.POST['CustomerName']
                # product_name = request.POST['product_name']

                feature_count = request.POST['feature_count']
                features_list = request.POST.getlist('Feature_ids')
                features = request.POST.getlist('features')
                Remark_count = request.POST['Remark_count']
                remarks = request.POST.getlist('remarks')
                # status= request.POST['status']
                status = Status.objects.get(name=request.POST['status'])
                added_by = CustomUser.objects.get(id=request.user.id)
                Timeline = request.POST['timeline']
                # features_list = ",".join(features)
                remarks_list = ",".join(remarks)

                new_poc = Poc_model(Customer_name=customer_name, Product_name=product_name, status=status,
                                    added_by=added_by, Timeline=Timeline)
                new_poc.save()

                poc_ref = Poc_model.objects.get(pk=new_poc.id)

                new_feature_list = []
                for feture in features:
                    new_feature_list.append(
                        {'poc_id': poc_ref, 'features_list': feture, 'status': status, 'added_by': added_by})
                new_feature_list = []
                for j in features_list:
                    new_feature_list.append({'poc_id': poc_ref, 'features_list': request.POST[f'features_{j}'],
                                             'timeline': request.POST[f'timeline_{j}'], 'status': status,
                                             'added_by': added_by})
                    # Access created features and their status objects:
                features_lsts_added = []
                for data in new_feature_list:
                    feature = Feature.objects.create(**data)  # Create the Feature object
                    status_data = Feature_status.objects.create(feature=feature, status=status,
                                                                added_by=added_by)  # Create the Status object linked to the Feature
                    features_lsts_added.append(status_data)
                messages.success(request, "POC added successfully.")
                new_remarks_list = []
                for remark in remarks:
                    new_remarks_list.append({'poc_id': poc_ref, 'remarks': remark, 'status': status, 'added_by': added_by})
                # new_fetures = Feature()
                # Feature.objects.bulk_create([Feature(**data) for data in new_feature_list])
                # new_remarks = Poc_remark()
                Poc_remark.objects.bulk_create([Poc_remark(**data) for data in new_remarks_list])
        except Exception as e:
            print(e)
            messages.error(request, f"POC not added {e}.", extra_tags="danger")

    context['product_list'] = product_list
    return render(request, 'poc_demo/add_poc.html', context)


@login_required(login_url='loginpage')
def add_user(request):
    flow = {"Admin": ['Admin', 'Manager', 'Sales'], "Manager": ['Sales'], "Sales": ''}
    user = User.objects.all()
    roles = Roles.objects.all()

    sts = status_choice
    context = {}
    context['users'] = [i.first_name for i in user]
    user_type_dict = dict()
    for emp in user:
        if emp.User_Type not in user_type_dict:
            user_type_dict[emp.User_Type] = []
        user_type_dict[emp.User_Type].append(emp.first_name)
    context['user_list'] = user_type_dict
    context['roles'] = roles
    context['status'] = sts
    if request.method == 'POST':
        result = dict()
        try:
            existing_user = User.objects.filter(email=request.POST['email']).first()

            if existing_user:
                messages.error(request, 'Email address already in use! Please choose a different one.', extra_tags="danger")
            else:
                Belongs_to = User.objects.get(id=request.POST['Belongs_to'])
                usertype = Roles.objects.get(name=request.POST['usertype'])
                if usertype.name == 'Support':
                    permissions_to_skip = ['delete', 'edit']  # Permissions Support shouldn't have
                else:
                    permissions_to_skip = []
                first_name = request.POST['first_name']
                last_name = request.POST['last_name']
                email = request.POST['email']
                username = request.POST['username']
                password = request.POST['password']
                status = request.POST.get('status')
                new_user = User.objects.create(first_name=first_name, last_name=last_name, email=email,
                                               username=username, Belongs_to=Belongs_to, role=usertype, Status=status)
                new_user.set_password(password)
                list_dict = {'poc': Poc_model, 'demo': Demo_model, 'fstatus': Feature_status,
                             'dstatus': Demo_Feature_status, 'user': User
                    , 'premark': Poc_remark, 'dremark': Demo_remark, 'pfeature': Feature, 'dfeature': Demo_feature}
                # for j in ['poc', 'demo', 'fstatus', 'dstatus', 'user', 'premark', 'dremark', 'pfeature', 'dfeature']:
                #     contenttype = ContentType.objects.get_for_model(list_dict[j])
                #     for i in ['add', 'delete', 'view', 'edit']:
                #         if i in permissions_to_skip:
                #             continue
                #         else: 
                #             print("************",usertype)

                #         review_permision = Permission.objects.create(
                #             codename = f"{i}_{j}",
                #             name =f"Can {i} {j}",
                #             content_type =contenttype
                #         )
                #         new_user.user_permissions.add(review_permision)

                # user_group = Group.objects.get_or_create(name=usertype.name)[0]
                # print(user_group)
                # new_user.groups.add(user_group)
                new_user.save()

                messages.success(request, 'User added successfully.')
        except Exception as e:
            messages.error(request, f'User not added {e}.', extra_tags="danger")
        return redirect('add_users')
    return render(request, 'poc_demo/add_user.html', context)


@login_required(login_url='loginpage')
def view_users(request):
    user = User.objects.all()
    if request.method == 'POST':
        pass
    context = {
        "users": user,
        "status": status_choice
    }

    return render(request, 'poc_demo/user_view.html', context)


@login_required(login_url='loginpage')
def edit_user(request, id):
    all_user = User.objects.all()
    user = get_object_or_404(User, pk=id)  # Fetch user by ID
    flow = {"Admin": ['Admin', 'Manager', 'Sales'], "Manager": ['Sales'], "Sales": ''}
    roles = Roles.objects.all()

    sts = status_choice
    context = {}
    user_type_dict = dict()

    if request.method == 'POST':
        try:
            existing_user = User.objects.filter(email=request.POST['email']).exclude(pk=user.id).first()

            if existing_user:
                messages.error(request, 'Email address already in use! Please choose a different one.', extra_tags="danger")
            else:
                user.first_name = request.POST['first_name']
                user.last_name = request.POST['last_name']
                user.email = request.POST['email']
                if request.POST['Belongs_to'] != 'None':
                    user.Belongs_to = User.objects.get(id=request.POST['Belongs_to'])

                user.role = Roles.objects.get(name=request.POST['usertype'])
                user.Status = request.POST.get('status')
                user.save()
                messages.success(request, f'User: {user.email} updated successfully.')
        except Exception as e:
            messages.error(request, f'User not updated {e}.', extra_tags="danger")
            return redirect('view_users')
    context = {'user': user,
               'roles': roles,
               'status': sts,
               'all_user': all_user
               }
    return render(request, 'poc_demo/edit_user.html', context)


@login_required(login_url='loginpage')
def add_product(request):
    context = dict()
    sts = status_choice
    context['status'] = sts
    if request.method == 'POST':
        result = dict()
        try:
            Product_name = (request.POST['product_name']).strip()
            existing_product = Product.objects.filter(Product_name=Product_name.lower()).first()
            if existing_product:
                messages.error(request, f"Product {Product_name} already Exist!",
                               extra_tags="danger")
            else:
                # Belongs_to = Users.objects.get(name=request.POST['Belongs_to'])
                status = request.POST.get('status')  #request.POST.get('status')
                new_product = Product(Product_name=Product_name, status=status,
                                      added_by=CustomUser.objects.get(id=request.user.id))
                new_product.save()
                messages.success(request, f"Product: {Product_name} added successfully.")
                # request.session['success_message'] = 'Successfully added!'
        except Exception as e:
            print(e)
            messages.error(request, f"Product not added {e}.", extra_tags="danger")
            # request.session['error_message'] = 'not added!'
            error_message = 'not added'
        return redirect('add_product')
    return render(request, 'poc_demo/add_product.html', context)


def view_product(request):
    product = Product.objects.all()
    context = {
        "products": product,
        "status": status_choice
    }
    return render(request, 'poc_demo/view_products.html', context)


@login_required(login_url='loginpage')
def add_role(request):
    context = dict()
    sts = status_choice
    context['status'] = sts
    if request.method == 'POST':
        result = dict()
        try:
            # if check Roles available and then create
            # Belongs_to = Users.objects.get(name=request.POST['Belongs_to'])  
            Role_name = (request.POST['role_name']).strip()
            existing = Roles.objects.filter(name=Role_name.lower()).first()
            if existing:
                messages.error(request, f"Role {Role_name} already Exist!",
                               extra_tags="danger")
            else:
                status = request.POST.get('status')
                new_role = Roles(name=Role_name, status=status)
                new_role.save()
                messages.success(request, f"Role: {request.POST['role_name']} added successfully.")
                # request.session['success_message'] = 'Successfully added!'
        except Exception as e:
            # request.session['error_message'] = 'not added!'
            messages.error(request, f"Role: {request.POST['role_name']} not added {e}.", extra_tags="danger")
        return redirect('add_role')
    return render(request, 'poc_demo/add_roles.html', context)


@login_required(login_url='loginpage')
def view_roles(request):
    roles = Roles.objects.all()
    if request.method == 'POST':
        pass
    context = {
        "roles": roles,
        "status": status_choice
    }
    return render(request, 'poc_demo/view_roles.html', context)


@login_required(login_url='loginpage')
def edit_role(request, id):
    try:
        # .exclude(pk=user.id)
        role = get_object_or_404(Roles, pk=id)
        roles_defined = ['Admin', 'Manager', 'Sales', 'Support']
        if request.method == "POST":
            Role_name = (request.POST['role_name']).strip()
            existing = Roles.objects.filter(name=Role_name.lower()).exclude(pk=id).first()
            if existing:
                messages.error(request, f"Role {Role_name} not updated, Role name already taken!", extra_tags="danger")
            else:
                role.name = request.POST['role_name']
                role.status = request.POST.get('status')
                role.save()
                messages.success(request, f"Role: {request.POST['role_name']} updated.")
    except Exception as e:
        messages.error(request, f"Role {request.POST['role_name']} not updated {e}.", extra_tags="danger")
    context = {'role': role,
               'status': status_choice,
               'roles_defined': roles_defined

               }
    return render(request, 'poc_demo/edit_role.html', context)


@login_required(login_url='loginpage')
def add_status(request):
    context = dict()
    if request.method == 'POST':
        result = dict()
        try:
            # Belongs_to = Users.objects.get(name=request.POST['Belongs_to'])
            sts = request.POST['status_name']
            if Status.objects.filter(name=(sts.strip()).lower()).count() > 0:
                messages.error(request, f'Status : {sts} alredy exist.', extra_tags="danger")
            else:
                Status.objects.create(name=sts, added_by=CustomUser.objects.get(id=request.user.id))
                messages.success(request, f"Status: {sts} added successfully.")

            return redirect('add_status')

            # request.session['success_message'] = 'Successfully added!'
        except Exception as e:
            # request.session['error_message'] = 'not added!'
            error_message = 'not added'
            messages.error(request, f"Status not added {e}.", extra_tags="danger")
            print(e)
        return redirect('add_status')
    return render(request, 'poc_demo/add_status.html', context)


@login_required(login_url='loginpage')
def view_status(request):
    new_sts = Status.objects.all()
    if request.method == 'POST':
        pass
    context = {
        "status": new_sts
    }
    return render(request, 'poc_demo/status_view.html', context)


@login_required(login_url='loginpage')
def edit_status(request, id):
    try:
        status = get_object_or_404(Status, pk=id)
        if request.method == "POST":
            if Status.objects.filter(name=request.POST['status_name'].lower()).exclude(pk=id).first():
                messages.error(request, f"Status: {request.POST['status_name']} alredy exist.", extra_tags="danger")
            else:
                status.name = request.POST['status_name']
                status.save()
                messages.success(request, f"Status: {request.POST['status_name']} updated.")
    except Exception as e:
        messages.error(request, f"Status: {request.POST['status_name']} not updated.", extra_tags="danger")
    context = {'status': status, }
    return render(request, 'poc_demo/edit_status.html', context)


@login_required(login_url='loginpage')
def edit_product(request, id):
    try:
        product = get_object_or_404(Product, pk=id)
        if request.method == "POST":
            if Product.objects.filter(Product_name=request.POST['product_name'].lower()).exclude(pk=id).first():
                messages.error(request, f"Product: {request.POST['product_name']} alredy exist.", extra_tags="danger")
            else:
                product.Product_name = request.POST['product_name']
                product.status = request.POST.get('status')  #request.POST.get('status')
                product.save()
                messages.success(request, f"Product: {request.POST['product_name']} updated.")
    except Exception as e:
        messages.error(request, f"Product: {request.POST['product_name']} not updated {e}.", extra_tags="danger")
    context = {
        'product': product,
        'status': status_choice
    }
    return render(request, 'poc_demo/edit_product.html', context)


@login_required(login_url='loginpage')
def view_poc(request):
    if request.user.role.name == "Admin":
        all_active_product = Poc_model.objects.prefetch_related('poc_f_related', 'poc_r_related').all()
    elif request.user.role.name == "Manager":
        all_active_product = Poc_model.objects.filter(added_by__Belongs_to=request.user.id).prefetch_related(
            'poc_f_related', 'poc_r_related').all()
    elif request.user.role.name == "Sales":
        all_active_product = Poc_model.objects.filter(added_by=request.user.id).prefetch_related('poc_f_related',
                                                                                                 'poc_r_related').all()
    elif request.user.role.name == "Support":
        all_active_product = Poc_model.objects.filter(assign_to=request.user.id).prefetch_related('poc_f_related',
                                                                                                  'poc_r_related').all()
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
            remarks = request.POST.getlist('remarks')
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
                new_remarks_list.append(
                    {'poc_id': get_poc, 'remarks': remark, 'status': get_poc.status, 'added_by': added_by})
            # new_remarks = Poc_remark()
            Poc_remark.objects.bulk_create([Poc_remark(**data) for data in new_remarks_list])
            return redirect('view_poc_detail', id=id)
    except Exception as e:
        print(e)
        return redirect('view_poc_detail', id=id)


def add_feature(request, id):
    try:
        if request.method == 'POST':
            added_by = CustomUser.objects.get(id=request.user.id)
            features_list = request.POST.getlist('Feature_ids')
            poc_ref = Poc_model.objects.get(pk=id)
            new_feature_list = []
            for j in features_list:
                new_feature_list.append({'poc_id': poc_ref, 'features_list': request.POST[f'features_{j}'],
                                         'timeline': request.POST[f'timeline_{j}'], 'status': 'Active',
                                         'added_by': added_by})
            features_lsts_added = []
            for data in new_feature_list:
                feature = Feature.objects.create(**data)  # Create the Feature object
                status_data = Feature_status.objects.create(feature=feature, status="active",
                                                            added_by=added_by)  # Create the Status object linked to the Feature
                features_lsts_added.append(status_data)
            messages.success(request, f"New feature: {','.join(features_lsts_added)} added successfully.")
            return redirect('view_poc_detail', id=id)
    except Exception as e:
        messages.error(request, f"New feature not added {e}.", extra_tags="danger")
        return redirect('view_poc_detail', id=id)


@login_required(login_url='loginpage')
def edit_poc(request, id):
    try:
        if request.method == 'POST':
            get_poc = Poc_model.objects.get(pk=id)
            if request.POST.get('product_name'):
                product_name = Product.objects.get(Product_name=request.POST['product_name'])
                get_poc.Product_name = product_name
            status = Status.objects.get(name=request.POST['status'])
            get_poc.Customer_name = request.POST['Customer_name']
            get_poc.Timeline = request.POST['Timeline_date']
            get_poc.status = status
            if request.POST.get('assign_edit'):
                if request.POST['assign_edit'] != 'None':
                    get_poc.assign_to = User.objects.get(pk=request.POST.get('assign_edit'))
            get_poc.save()
            messages.success(request, 'POC updated.')
    except Exception as e:
        messages.error(request, f"POC not edited {e}.", extra_tags="danger")
    return redirect('view_poc_detail', id=id)


@login_required(login_url='loginpage')
def update_sts(request, id):
    if request.method == 'POST':
        try:
            sts_id = request.POST['sts_id']
            status = request.POST['status']
            poc_id = request.POST['poc_id']
            added_by = CustomUser.objects.get(id=request.user.id)
            featureobj = Feature.objects.get(pk=sts_id)
            Feature_status.objects.create(feature=featureobj, status=status, added_by=added_by)
            # return redirect('view_poc_detail', id=id)
            return HttpResponse(
                f'<div class="messages text-center alert alert-danger"> <h2> status  added.</h2> </div>')

        except Exception as e:
            # return redirect('view_poc_detail', id=id)
            return HttpResponse(
                f'<div class="messages text-center alert alert-danger"> <h2> status not added {e}.</h2> </div>')


@login_required(login_url='loginpage')
def update_feature_detail(request):
    if request.method == 'POST':
        try:
            id = request.POST['id']
            feature = get_object_or_404(Feature, pk=id)
            feature.features_list = request.POST['Feature_name']
            feature.status = request.POST['status']
            feature.timeline = request.POST['Feature_timeline']
            feature.added_by = CustomUser.objects.get(id=request.user.id)
            feature.save()
            messages.success(request, f"Feature: {request.POST['Feature_name']} updated.")
            return HttpResponse(
                '<div class="messages text-center alert alert-success"> <h2>  updated.</h2> </div>')  #just for testing purpose you can remove it.
        except Exception as e:
            messages.error(request, f"Feture not updated {e}.", extra_tags="danger")
            return HttpResponse(
                f'<div class="messages text-center alert alert-danger"> <h2>  not updated {e}.</h2> </div>')


@login_required(login_url='loginpage')
def view_poc_detail(request, id):
    poc = Poc_model.objects.prefetch_related('poc_f_related', 'poc_r_related').get(id=id)
    permission_for_edit = ['Admin', 'Sales', 'Manager']
    permission_for_delete = ['Admin', 'Sales', 'Manager']
    permission_for_ADD_STATUS = ['Admin', 'Sales', 'Manager', 'Support']
    html_feture_only = ''' '''
    html_feture_sts_only = ''' '''
    html = ''' '''
    for feature in poc.poc_f_related.all():
        elated_objects_count = feature.feature_related.count() + 1
        for data in feature.feature_related.all().order_by('-created_at'):
            html += f'''
                    <tr>
                    <td>{data.status}</td>
                      <td>{data.added_by}</td>
                      <td>{data.created_at}</td>
                      </tr>'''
            html_feture_sts_only += f'''
                    <tr>
                     <td>{feature.features_list}</td>
                    <td>{data.status}</td>
                      <td>{data.added_by}</td>
                      <td>{data.created_at}</td>
                      </tr>'''
    all_active_product = Product.objects.all()
    status_list = Status.objects.all()
    assign_to = User.objects.filter(role=4)
    permition = [1, 2, 3]
    if request.method == 'POST':
        try:
            Remark_count = request.POST['Remark_count']
            remarks = request.POST.getlist('remarks')
            # status= request.POST['status'] 
            added_by = CustomUser.objects.get(id=request.user.id)
            rid = request.POST['row_remark_id']
            get_poc = Poc_model.objects.get(pk=rid)
            new_remarks_list = []
            for remark in remarks:
                new_remarks_list.append(
                    {'poc_id': get_poc, 'remarks': remark, 'status': get_poc.status, 'added_by': added_by})
            Poc_remark.objects.bulk_create([Poc_remark(**data) for data in new_remarks_list])
            return redirect('view_poc_detail', id=id)
        except Exception as e:
            print(e)
    return render(request, 'poc_demo/view_poc_detail.html', {'data': poc,
                                                             'status': status_list,
                                                             'html': html,
                                                             'product': all_active_product,
                                                             'permition': [1, 2, 3],
                                                             "assign_to": assign_to,
                                                             "html_feture_sts_only": html_feture_sts_only,
                                                             "html_feture_only": html_feture_only,
                                                             "permission_for_edit": permission_for_edit,
                                                             "permission_for_ADD_STATUS": permission_for_ADD_STATUS,
                                                             "permission_for_delete": permission_for_delete
                                                             })


@login_required(login_url='loginpage')
def get_detail_sts(request):
    sts_data = dict()
    if request.method == 'POST':
        id = request.POST.get('id')
        feature = Feature.objects.get(pk=id)
        get_data = Feature_status.objects.filter(feature=feature).order_by('-created_at')

        for data in get_data:
            sts_data[f'new_{data.id}'] = {'status': data.status, 'added_by': data.added_by.username,
                                          'time': data.created_at, 'feature': feature.features_list}
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
        messages.success(request, 'Role deleted.')
        pass
    except Exception as e:
        messages.error(request, f'Role not deleted {e}.', extra_tags='danger')
    return redirect('view_roles')


@login_required(login_url='loginpage')
def delete_product(request, id):
    try:
        Product.objects.get(pk=id).delete()
        messages.success(request, 'Product deleted.')
    except Exception as e:
        messages.error(request, f'Product not deleted {e}.', extra_tags='danger')
    return redirect('view_product')


@login_required(login_url='loginpage')
def delete_user(request, id):
    try:
        User.objects.get(pk=id).delete()
        messages.success(request, 'User deleted.')
    except Exception as e:
        messages.error(request, f'User not deleted {e}.', extra_tags='danger')
    return redirect('view_users')


@login_required(login_url='loginpage')
def delete_status(request, id):
    try:
        Status.objects.get(pk=id).delete()
        messages.success(request, 'Status deleted.')
    except Exception as e:
        messages.error(request, f'Status not deleted {e}.', extra_tags='danger')
    return redirect('view_status')


@login_required(login_url='loginpage')
def add_demo(request):
    all_active_product = Product.objects.all()
    sts = Status.objects.all()
    context = {}
    context['status'] = sts
    product_list = [product for product in all_active_product]

    if request.method == 'POST':
        try:
            customer_name = request.POST['CustomerName']
            # product_name = request.POST['product_name']
            product_name = Product.objects.get(Product_name=request.POST['product_name'])
            feature_count = request.POST['feature_count']
            features_list = request.POST.getlist('Feature_ids')
            features = request.POST.getlist('features')
            Remark_count = request.POST['Remark_count']
            remarks = request.POST.getlist('remarks')
            # status= request.POST['status'] 
            status = Status.objects.get(name=request.POST['status'])
            added_by = CustomUser.objects.get(id=request.user.id)
            Timeline = request.POST['timeline']
            # features_list = ",".join(features)
            remarks_list = ",".join(remarks)

            new_demo = Demo_model(Customer_name=customer_name, Product_name=product_name, status=status,
                                  added_by=added_by, Timeline=Timeline)
            new_demo.save()

            demo_ref = Demo_model.objects.get(pk=new_demo.id)
            new_feature_list = []
            for j in features_list:
                new_feature_list.append({'demo_id': demo_ref, 'features_list': request.POST[f'features_{j}'],
                                         'timeline': request.POST[f'timeline_{j}'], 'status': status,
                                         'added_by': added_by})
            # Access created features and their status objects:
            features_lsts_added = []
            for data in new_feature_list:
                feature = Demo_feature.objects.create(**data)  # Create the Feature object
                status_data = Demo_Feature_status.objects.create(feature=feature, status=status,
                                                                 added_by=added_by)  # Create the Status object linked to the Feature
                features_lsts_added.append(status_data)
            messages.success(request, "Demo added successfully.")
            new_remarks_list = []
            for remark in remarks:
                new_remarks_list.append(
                    {'demo_id': demo_ref, 'remarks': remark, 'status': status, 'added_by': added_by})
            Demo_remark.objects.bulk_create([Demo_remark(**data) for data in new_remarks_list])
        except Exception as e:
            print(e)
            messages.error(request, f"Demo not added {e}.", extra_tags="danger")

    context['product_list'] = product_list
    return render(request, 'poc_demo/add_demo.html', context)


@login_required(login_url='loginpage')
def view_demo(request):
    if request.user.role_id == 1:
        all_active_product = Demo_model.objects.prefetch_related('demo_f_related', 'demo_r_related').all()
    elif request.user.role_id == 3:
        all_active_product = Demo_model.objects.filter(added_by__Belongs_to=request.user.id).prefetch_related(
            'demo_f_related', 'demo_r_related').all()
    elif request.user.role_id == 2:
        all_active_product = Demo_model.objects.filter(added_by=request.user.id).prefetch_related('demo_f_related',
                                                                                                  'demo_r_related').all()
    elif request.user.role_id == 4:
        all_active_product = Demo_model.objects.filter(assign_to=request.user.id).prefetch_related('demo_f_related',
                                                                                                   'demo_r_related').all()
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

    return render(request, 'poc_demo/view_demo.html', context)


@login_required(login_url='loginpage')
def view_demo_detail(request, id):
    permission_for_edit = ['Admin', 'Sales', 'Manager']
    permission_for_delete = ['Admin', 'Sales', 'Manager']
    permission_for_ADD_STATUS = ['Admin', 'Sales', 'Manager', 'Support']
    demo = Demo_model.objects.prefetch_related('demo_f_related', 'demo_r_related').get(id=id)
    html_feture_only = ''' '''
    html_feture_sts_only = ''' '''
    html = ''' '''
    for feature in demo.demo_f_related.all():
        elated_objects_count = feature.demo_feature_related.count() + 1
        for data in feature.demo_feature_related.all().order_by('-created_at'):
            html += f'''
                    <tr>
                    <td>{data.status}</td>
                      <td>{data.added_by}</td>
                      <td>{data.created_at}</td>
                      </tr>'''
            html_feture_sts_only += f'''
                    <tr>
                     <td>{feature.features_list}</td>
                    <td>{data.status}</td>
                      <td>{data.added_by}</td>
                      <td>{data.created_at}</td>
                      </tr>'''
    all_active_product = Product.objects.all()
    status_list = Status.objects.all()
    assign_to = User.objects.filter(role=4)
    permition = [1, 2, 3]
    if request.method == 'POST':
        try:
            Remark_count = request.POST['Remark_count']
            remarks = request.POST.getlist('remarks')
            # status= request.POST['status'] 
            added_by = CustomUser.objects.get(id=request.user.id)
            rid = request.POST['row_remark_id']
            get_demo = Demo_model.objects.get(pk=rid)
            new_remarks_list = []
            for remark in remarks:
                new_remarks_list.append(
                    {'poc_id': get_demo, 'remarks': remark, 'status': get_demo.status, 'added_by': added_by})
            Demo_remark.objects.bulk_create([Demo_remark(**data) for data in new_remarks_list])
            return redirect('view_demo_detail', id=id)
        except Exception as e:
            print(e)
    return render(request, 'poc_demo/view_demo_detail.html', {'data': demo,
                                                              'status': status_list,
                                                              'html': html,
                                                              'product': all_active_product,
                                                              'permition': [1, 2, 3],
                                                              "assign_to": assign_to,
                                                              "html_feture_sts_only": html_feture_sts_only,
                                                              "html_feture_only": html_feture_only,
                                                              "permission_for_edit": permission_for_edit,
                                                              "permission_for_ADD_STATUS": permission_for_ADD_STATUS,
                                                              "permission_for_delete": permission_for_delete
                                                              })


@login_required(login_url='loginpage')
def edit_demo(request, id):
    try:
        if request.method == 'POST':
            get_demo = Demo_model.objects.get(pk=id)
            if request.POST.get('product_name'):
                product_name = Product.objects.get(Product_name=request.POST['product_name'])
                get_demo.Product_name = product_name

            status = Status.objects.get(name=request.POST['status'])
            get_demo.Customer_name = request.POST['Customer_name']
            get_demo.Timeline = request.POST['Timeline_date']
            get_demo.status = status
            if request.POST.get('assign_edit'):
                if request.POST['assign_edit'] != 'None':
                    get_demo.assign_to = User.objects.get(pk=request.POST.get('assign_edit'))
            get_demo.save()
            messages.success(request, 'Demo Updated.')
    except Exception as e:
        messages.error(request, f"Demo not updated {e}.", extra_tags="danger")
    return redirect('view_demo_detail', id=id)


@login_required(login_url='loginpage')
def add_demo_remarks(request, id):
    try:
        if request.method == 'POST':
            Remark_count = request.POST['Remark_count']
            remarks = request.POST.getlist('remarks')
            added_by = CustomUser.objects.get(id=request.user.id)
            rid = request.POST['row_remark_id']
            get_demo = Demo_model.objects.get(pk=rid)
            new_remarks_list = []
            for remark in remarks:
                new_remarks_list.append(
                    {'demo_id': get_demo, 'remarks': remark, 'status': get_demo.status, 'added_by': added_by})
            # new_remarks = Poc_remark()
            Demo_remark.objects.bulk_create([Demo_remark(**data) for data in new_remarks_list])
            messages.success(request, f'Demo remark {",".join(new_remarks_list)} added.')
            return redirect('view_demo_detail', id=id)
    except Exception as e:
        messages.error(request, f'Demo remark: {",".join(new_remarks_list)} not added {e}.',  extra_tags="danger")
        return redirect('view_demo_detail', id=id)


@login_required(login_url='loginpage')
def add_demo_feature(request, id):
    try:
        if request.method == 'POST':
            added_by = CustomUser.objects.get(id=request.user.id)
            features_list = request.POST.getlist('Feature_ids')
            demo_ref = Demo_model.objects.get(pk=id)
            new_feature_list = []
            for j in features_list:
                new_feature_list.append({'demo_id': demo_ref, 'features_list': request.POST[f'features_{j}'],
                                         'timeline': request.POST[f'timeline_{j}'], 'status': 'Active',
                                         'added_by': added_by})
            features_lsts_added = []
            for data in new_feature_list:
                feature = Demo_feature.objects.create(**data)  # Create the Feature object
                status_data = Demo_Feature_status.objects.create(feature=feature, status="active",
                                                                 added_by=added_by)  # Create the Status object linked to the Feature
                features_lsts_added.append(status_data)
            messages.success(request, f"New feature: {','.join(features_lsts_added)} added successfully.")
            return redirect('view_demo_detail', id=id)
    except Exception as e:
        messages.error(request, f"New feature not added {e}.", extra_tags="danger")
        return redirect('view_demo_detail', id=id)


@login_required(login_url='loginpage')
def get_detail_sts_demo(request):
    sts_data = dict()
    if request.method == 'POST':
        id = request.POST.get('id')
        feature = Demo_feature.objects.get(pk=id)
        get_data = Demo_Feature_status.objects.filter(feature=feature).order_by('-created_at')

        for data in get_data:
            sts_data[f'new_{data.id}'] = {'status': data.status, 'added_by': data.added_by.username,
                                          'time': data.created_at, 'feature': feature.features_list}
    return JsonResponse(sts_data)


@login_required(login_url='loginpage')
def demo_update_sts(request, id):
    if request.method == 'POST':
        try:
            sts_id = request.POST['sts_id']
            status = request.POST['status']
            demo_id = request.POST['demo_id']
            added_by = CustomUser.objects.get(id=request.user.id)
            featureobj = Demo_feature.objects.get(pk=sts_id)
            Demo_Feature_status.objects.create(feature=featureobj, status=status, added_by=added_by)
            messages.success(request, f" Status: {status} added.")
            # return redirect('view_poc_detail', id=id)
            return HttpResponse(
                f'<div class="messages text-center alert alert-danger"> <h2> status  added.</h2> </div>')
        except Exception as e:
            messages.error(request, f"Status {request.POST['status']} not added.", extra_tags="danger")
            # return redirect('view_poc_detail', id=id)
            return HttpResponse(
                f'<div class="messages text-center alert alert-danger"> <h2> status not added {e}.</h2> </div>')


@login_required(login_url='loginpage')
def update_feature_detail_demo(request):
    if request.method == 'POST':
        try:
            id = request.POST['id']
            feature = get_object_or_404(Demo_feature, pk=id)
            feature.features_list = request.POST['Feature_name']
            feature.status = request.POST['status']
            feature.timeline = request.POST['Feature_timeline']
            feature.added_by = CustomUser.objects.get(id=request.user.id)
            feature.save()
            messages.success(request, f"Feature : {feature.features_list} updated.")
            return HttpResponse(
                '<div class="messages text-center alert alert-success"> <h2>  updaed.</h2> </div>')  #just for testing purpose you can remove it.
        except Exception as e:
            messages.error(request, f"Feature : {feature.features_list} not updated {e}.", extra_tags="danger")
            return HttpResponse(
                f'<div cla  ss="messages text-center alert alert-danger"> <h2>  not updated {e}.</h2> </div>')


def delete_feature(request):
    if request.method == 'POST':
        try:
            if request.POST['slug'] == 'demo':
                feature = get_object_or_404(Demo_feature, pk=int(request.POST['id']))  # Adjust model access logic
                feature.delete()
            else:
                feature = get_object_or_404(Feature, pk=int(request.POST['id']))  # Adjust model access logic
                feature.delete()
            messages.success(request, f"Feature Deleted.")
            return JsonResponse({'success': True, 'message': 'Feature deleted successfully'})
        except Exception as e:
            messages.error(request, f"Feature  not deleted.", extra_tags="danger")
            return JsonResponse({'success': False, 'message': f'Error deleting feature: {e}'})
    else:
        return JsonResponse({'success': False, 'message': 'Invalid request method'})
