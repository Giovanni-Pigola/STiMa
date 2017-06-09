import random
import datetime

from django.shortcuts import render
from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.contrib.auth import authenticate, login, logout
from django import forms
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.utils.crypto import get_random_string

from .models import manager

def home(request):
    return render(request, 'home.html')

def user_login(request):
    #desativada = False
    errado = False
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(username=username, password=password)
        if user:
            if user.is_active:
                login(request, user)
                return HttpResponseRedirect('/home/')
            #else:
            #   desativada = True
        else:
            errado = True
    return render(request, 'login.html', {'errado': errado})  #{'desativada': desativada, 'errado': errado})

def user_logout(request):
    logout(request)
    return HttpResponseRedirect('/home/')

#
#
#
#  Modificar Isso
def redefinirSenha(request):
    finalizado = False
    invalido = False
    if request.method == 'POST':
        form = RedefinirSenhaForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['emailForm']
            senhaNova = get_random_string(length=8)
            try:
                usuario = User.objects.get(email=email)
                send_mail('Redefinição de senha no site Gameception',
                          'Sua senha foi redefinida para: ' + senhaNova + '. Essa senha pode ser alterada a qualquer momento, para isso basta acessar o site e clicar em "Alterar Senha", através do menu "Minha Conta"',
                          'support@gameception.com', [email])
                usuario.set_password(senhaNova)
                usuario.save()
                finalizado = True
            except:
                invalido = True
    else:
        form = RedefinirSenhaForm()
    return render(request, 'home.html', {'form': form, 'finalizado': finalizado, 'invalido': invalido})

# Form
class UserForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput())
    class Meta:
        model = User
        fields = ('username', 'email', 'password')
    def __init__(self, *args, **kwargs):
        super(UserForm, self).__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            field.widget.attrs['class'] = 'form-control'

# Form Redefinir Senha
class RedefinirSenhaForm(forms.Form):
    emailForm = forms.EmailField(label='email', widget=forms.TextInput(attrs={'placeholder': 'E-mail'}))
    def __init__(self, *args, **kwargs):
        super(RedefinirSenhaForm, self).__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            field.widget.attrs['class'] = 'form-control'

