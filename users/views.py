from __future__ import unicode_literals
from django.shortcuts import render
from django.http import HttpResponse
from django.http import HttpResponseRedirect
from .models import user
from django.contrib.auth import login, authenticate
from django.contrib import messages
from passlib.hash import pbkdf2_sha256
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.core.mail import EmailMessage
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.models import User
from django.utils.encoding import force_bytes, force_text
from .tokens import account_activation_token

def index(request):
    return render(request,'users/index.html')

def play(request):
    if request.method == "POST":
        alluser = user.objects.all()
        playerss = []
        for obj in alluser:
            if obj.email in request.POST:
                playerss.append(obj)
        players=[]
        names=[]
        for i in playerss:
            players.append(request.POST.get(i.email))
            names.append(i.name)
        params={'names':names,'players':players}
        return render(request,'users/ludo.html',params)
    else:
        return HttpResponse("invalid request")

def mylogin(request):
    if not request.session.get('slogin',False):
        return render(request,'users/mylogin.html')
    messages.error(request,'Already logged in')
    return HttpResponseRedirect(request.META.get('HTTP_REFERER'))

def viewProfile(request):
    try:
        tuser = user.objects.get(email=request.session['loguser'])
        params={'profile':tuser}
        return render(request,'users/viewProfile.html',params)
    except:
        messages.error(request,'Please login')
        return HttpResponseRedirect('/users/mylogin')

def SelectUser(request):
    if request.session['slogin']:
        alluser = user.objects.all().exclude(email=request.session['loguser'])
        return render(request,'users/alluser.html',{'alluser':alluser})
    else:
        messages.error(request,'Please login')
        return HttpResponseRedirect('/users/mylogin')

def choosecolor(request):
    if request.session['slogin']:
        alluser = user.objects.all()
        players = []
        for obj in alluser:
            if obj.email in request.POST:
                players.append(obj)
        thisuser = user.objects.get(email=request.session['loguser'])
        players.append(thisuser)
        return render(request,'users/choosecolor.html',{'players':players})
    else:
        messages.error(request,'Please login')
        return HttpResponseRedirect('users/mylogin.html')


def updateProfile(request):
    if request.method=='POST':
        if request.session.get('slogin',False):
            tprofilepic=request.FILES.get("profilePic",None)
            profile= user.objects.get(email=request.session['loguser'])
            profile.profilePic=tprofilepic
            profile.save()
            return HttpResponseRedirect('viewProfile')
        else:
            messages.error(request,"please login to update profile")
            return HttpResponseRedirect('mylogin')

def updateName(request):
    if request.method=='POST':
        if request.session.get('slogin',False):
            tfirstname=request.POST.get("firstname","none")
            tlastname=request.POST.get("lastname","none")
            profile= user.objects.get(email=request.session['loguser'])
            profile.name=tfirstname+" "+tlastname
            profile.save()
            return HttpResponseRedirect('viewProfile')
        else:
            messages.error(request,"please login to update profile Name")
            return HttpResponseRedirect('mylogin')

def mylogout(request):
    request.session['slogin']=False
    request.session['loguser']='None'
    request.session['loggedin']=False
    return HttpResponseRedirect('/')


def handlelogin(request):
    if request.method == "POST":
        if not request.session.get('slogin',False):
            temail=request.POST.get('email')
            tpassword=request.POST.get('password')
            try:
                details=user.objects.get(email=temail)
            except:
                messages.error(request, 'wrong credentials')
                return HttpResponseRedirect('mylogin')
            if pbkdf2_sha256.verify(tpassword,details.password):
                if not details.isActive:
                    return HttpResponse('Please verify your Email')
                request.session['slogin']=True
                request.session['loguser']=temail
                request.session['loggedin']=True
                messages.success(request, 'You are logged in succesfully')
                return HttpResponseRedirect('/users')
            else:
                messages.error(request, 'wrong credentials')
                return HttpResponseRedirect('mylogin')
        else:
            return HttpResponseRedirect('/users')
    else:
        return HttpResponse("invalid request")

def signup(request):
    return render(request,'users/signup.html')

def handlesignup(request):
    if request.method == "POST":
        tname=request.POST.get('name','none')
        temail=request.POST.get('email','none')
        tpassword=request.POST.get('password','none')
        tprofilepic=request.FILES.get('profilePic','none')
        test=user.objects.filter(email=temail)
        if len(test)==1:
            messages.error(request, 'User already exist with this email')
            return HttpResponseRedirect('signup')
        enc_string=pbkdf2_sha256.encrypt(tpassword,rounds=12000,salt_size=32)
        tuser=user(name=tname,email=temail,password=enc_string,profilePic=tprofilepic,isActive=False)
        current_site = get_current_site(request)
        mail_subject = 'Please verify  your  email.'
        message = render_to_string('users/acc_active_email.html',{
                'user': tuser,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(temail)),
                'token': account_activation_token.make_token(tuser),
            })
        to_email = temail
        email = EmailMessage(
                mail_subject, message, to=[to_email]
            )
        email.send()
        tuser.save()
        return HttpResponse("Verify your Email")
    else:
        return HttpResponse("invalid")

def UserActivate(request, uidb64, token):
    tpflag=True
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        tuser = user.objects.get(email=uid)
    except:
        tpflag=False
    if tpflag and account_activation_token.check_token(tuser, token):
        tuser.isActive = True
        tuser.save()
        return HttpResponseRedirect('/users/mylogin')
    else:
        return HttpResponse('Activation link is invalid!')


def forgetpassword(request):
    if not request.session.get('slogin',False):
        return render(request,'users/forgetpassword.html')
    else:
        return HttpResponseRedirect('/')

def handleforgetpassword(request):
    if request.method=="POST":
        tempmail=request.POST.get('email')
        tuser=user.objects.get(email=tempmail)
        tuser.isActive=False
        tuser.save()
        current_site = get_current_site(request)
        mail_subject = 'Change Your Password'
        message = render_to_string('users/change_pass_email.html', {
                'user':tuser,
                'domain': current_site.domain,
                'uid':urlsafe_base64_encode(force_bytes(tempmail)),
                'token':account_activation_token.make_token(tuser),
            })
        to_email = tempmail
        email = EmailMessage(
                        mail_subject, message,to=[to_email]
            )
        email.send()
        messages.success(request,'Please check your email to change the Password')
        return HttpResponse('Please check your email to change the Password')
    else:
        return HttpResponse("invalid request")

def changePassword(request,uidb64,token):
    tpflag=True
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        tuser = user.objects.get(email=uid)
    except:
        tpflag=False
    if tpflag and account_activation_token.check_token(tuser, token):
        request.session['uid']=uidb64
        return render(request,'users/changepassword.html')
    else:
        return HttpResponse('Activation link is invalid!')

def handleChangePassword(request):
    if request.method=='POST':
        tpflag=True
        try:
            uid = force_text(urlsafe_base64_decode(request.session.get('uid','None')))
            tuser = user.objects.get(email=uid)
            del request.session['uid']
        except:
            tpflag=False
            return HttpResponse("invalid url")
        newp=request.POST.get('newP')
        cnewP=request.POST.get('cnewP')
        if tpflag and cnewP and newp==cnewP:
            enc_string=pbkdf2_sha256.encrypt(newp,rounds=12000,salt_size=32)
            user.objects.filter(email=uid).update(password=enc_string)
            tuser.password=enc_string
            tuser.isActive=True
            tuser.save()
            messages.success(request,"password changed ")
            return HttpResponseRedirect('mylogin')
        else:
            messages.error(request,"password is not valid")
            return HttpResponseRedirect('/')
    else:
        return HttpResponse("invalid request")
