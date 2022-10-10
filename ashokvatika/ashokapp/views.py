from django.shortcuts import render

# Create your views here.
from django.contrib.auth.tokens import default_token_generator
from django.http.response import HttpResponse, HttpResponseRedirect
from django.views.generic.edit import FormView
from .form import SignupForm
from django.utils.encoding import force_bytes
from django.shortcuts import redirect, render
from django.contrib.auth.forms import PasswordResetForm, UserCreationForm
from django.contrib.auth import authenticate, login
from django.utils.http import urlsafe_base64_encode
from django.utils.http import urlsafe_base64_decode
from django.template.loader import render_to_string
from django.contrib.auth import logout
from django.contrib.sites.shortcuts import get_current_site
from .tokens import account_activation_token
from django.utils.encoding import force_text
from django.contrib.auth.models import User
from .tokens import account_activation_token
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login
from django.core.mail import send_mail
from django.core.mail import EmailMessage
from django.conf import settings
# Create your views here
# from django.urls import reverse_lazy
# from django.utils.decorators import method_decorator
# from django.views.decorators.csrf import csrf_protect

# from django.contrib.auth import views as auth_views
from django.contrib import messages
@login_required
def index(request):
    return render(request, 'index.html')


def home(request):
    return render(request, 'index.html')


def Signup(request):
    if request.method == 'POST':
        form = SignupForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False
            email=form.cleaned_data.get('email')
            user.save()
            # '127.0.0.1:8000'                                           #get_current_site(request)
            current_site = get_current_site(request)
            message = render_to_string('account_activation_email.html', {
                'user': user,
                'domain': current_site.domain,  # '127.0.0.1:8000' , current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),


                'token': account_activation_token.make_token(user),
            })
            subject = 'Activate Your  Account'
            user.email_user(subject, message)
        
            emailsend=EmailMessage(subject,message,from_email=settings.EMAIL_HOST_USER,to=[email])
            emailsend.send()
            send_mail(
                subject,
                message,
                settings.EMAIL_HOST_USER,
                [email],
                fail_silently=False,
            )
            return redirect('account_activation_sent')
            # username=form.cleaned_data.get('username')
            # raw_password=form.cleaned_data.get('password1')
            # user=authenticate(username=username,password=raw_password)
            # login(request,user)
            # return redirect('/index')
    else:
        form = SignupForm()
    return render(request, 'signup.html', {'form': form})


def LoginUser(request):
   
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)
            messages.add_message(request, messages.SUCCESS,
                                 "Successfully Login.")
            # A backend authenticated the credentials
            return redirect("/")
        else:
            # No backend authenticated the credentials
            messages.add_message(request, messages.ERROR,
                                 "You don't have an account.")
            return render(request, 'login.html')
    return render(request, 'login.html')


def account_activation_sent(request):
    return render(request, 'account_activation_sent.html')

def LogoutUser(request):
    logout(request)
    return redirect("")
def activate(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.profile.email_confirmed = True
        user.save()
        login(request, user)
        return redirect('home')
    else:
        return render(request, 'account_activation_invalid.html')


