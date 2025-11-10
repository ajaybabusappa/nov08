import json, jwt, datetime
import bcrypt
from django.http import JsonResponse
from django.shortcuts import render
from .serailisers import UserSerialiser
from .models import User
from django.views.decorators.csrf import csrf_exempt
from .passwords import password_hash

# Create your views here.


from django.conf import settings
SECRET_KEY = settings.SECRET_KEY


def home_page(request):
    try:

        auth_token = request.headers.get('Authorization')
        auth_token = auth_token.split(' ')[1]

        user_info = jwt.decode(auth_token, SECRET_KEY, algorithms='HS256')
        print(user_info)
    
    except Exception as e:
        return JsonResponse({'error': 'User verification failed'})

    loc = user_info['username']

    return JsonResponse({'status': 200, 'message': 'Showing home page' + 'of '+ loc})
    

@csrf_exempt
def register(request):
    print(request.body)
    data = json.loads(request.body)

    u1 = UserSerialiser(data = data)
    if u1.is_valid():
        print(u1.validated_data)
        # sent_password = u1.validated_data['password'].encode('utf-8')
        # salt = bcrypt.gensalt(rounds=12)
        # hashed_password = bcrypt.hashpw(sent_password, salt)
        hashed_password = password_hash(u1.validated_data['password'])
        u1.validated_data['password'] = hashed_password

        u1.save()
        return JsonResponse({'status': 'user_created', 'data': u1.data})
    else:
        return JsonResponse(u1.errors)


@csrf_exempt
def login(request):


    data = json.loads(request.body)
    try:
        u1 = User.objects.get(username = data['username'])
    except Exception as e:
        return JsonResponse({'error': 'login failed...check UN and PW'})

    entered_password = data['password']
    database_password = u1.password

    if bcrypt.checkpw(entered_password.encode('utf-8'), database_password.encode('utf-8')):
        data = {
            'username': u1.username,
            'location': 'India',
            'role': 'admin',
            'iat': datetime.datetime.now(datetime.timezone.utc)
        }

        token = jwt.encode(data, SECRET_KEY, algorithm='HS256')
        
        
        response = JsonResponse({'status': 200 , 'user_token': token})
        
        return response


    return JsonResponse({'status': 'login failed...check UN and PW'})


@csrf_exempt
def update(request):

    if not 'is_logged_in' in request.COOKIES:
        return JsonResponse({'error': 'login in first'})


    data = json.loads(request.body)

    try:
        u1 = User.objects.get(username = data.get('username'))
    except Exception as e:
        return JsonResponse({'error': 'User not found'})
    
    sent_password = data.get('password').encode('utf-8')
    salt = bcrypt.gensalt(rounds=12)
    hashed_password = bcrypt.hashpw(sent_password, salt)
    data['password'] = hashed_password.decode('utf-8')

    u1 = UserSerialiser(u1, data=data, partial = True)
    if u1.is_valid():
        u1.save()
        return JsonResponse({'status': 'Password changed'})
    else:
        return JsonResponse(u1.errors)




# def set_cookie(request):
#     response =  JsonResponse({})
#     response.set_cookie(
#         key  = 'theme',
#         value= 'dark',
#         max_age= 10
#     )
#     return response





def log_out(request):
    try:
        response = JsonResponse({"status": 'logged out'})
        response.delete_cookie('username')
        response.delete_cookie('is_logged_in')
        return response
    except:
        return JsonResponse({'status': 'logout failed'})
