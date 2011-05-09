# -*- coding: utf-8 -*-  
import os, datetime
#import time, pdb, logging, uuid, math, random, calendar

from urllib import quote, unquote, urlencode
from django.conf import settings
from django.shortcuts import render_to_response, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseRedirect, HttpResponse, Http404
from django.core.paginator import Paginator, EmptyPage, InvalidPage
from django.template import RequestContext
from django.contrib.auth import authenticate, login, logout
from django import forms
#from massivecoupon.paypalxpress.driver import PayPal
#from massivecoupon.paypalxpress.models import PayPalResponse
from django.contrib.auth.models import User
from massive002.engine.tcp import cidades 
from massive002.engine.models import EmailInscricao, Cupon, STATUS_ATIVO, STATUS_EMESPERA, Oferta, Cidade
from massive002.engine.forms import FormBuscar,CadastrarForm,LoginForm,OfertaCheckoutForm,EmailInscForm
#mapa
from gmapi import maps
from gmapi.forms.widgets import GoogleMap
#geoip
from django.contrib.gis.utils import GeoIP



def registra_usuario(request):
    cidades = Cidade.objects.all()

    if request.method == 'POST': # If the form has been submitted...
        form = CadastrarForm(request.POST)

        if form.is_valid():
            cd = form.cleaned_data

            user = User()
            user.username = cd.get('email')  #str(uuid.uuid4())[:30]
            user.first_name = cd.get('nome_completo')
            user.email = cd.get('email')
            user.save()
            user.set_password( cd.get('senha') )
            user.save()

            user = authenticate(username=user.username, password=cd.get('senha'))
            if user is not None:
                if user.is_active:
                    login(request, user)
                    # Redirect to a success page.
                else:
                    pass
                    # Return a 'disabled account' error message
            else:
                # Return an 'invalid login' error message.
                pass

            return HttpResponseRedirect('/')

    else:
        initial_data = {}
        form = CadastrarForm(initial=initial_data)

    return render_to_response('usuario/registra_usuario.html', {
                'form' : form,
                'cidades' : cidades,
              }, context_instance=RequestContext( request ) )


def logout_usuario(request):
    logout(request)
    return HttpResponseRedirect('/')


def login_usuario(request):
    cidades = Cidade.objects.all()

    if request.method == 'POST': # If the form has been submitted...
        form = LoginForm(request.POST)

        if form.is_valid():
            cd = form.cleaned_data

            login(request, form.user)

            return HttpResponseRedirect('/')

    else:
        initial_data = {}
        form = LoginForm(initial=initial_data)

    return render_to_response('usuario/login_usuario.html', {
                'form' : form,
                'cidades' : cidades,
              }, context_instance=RequestContext( request ) )

def termos(request):
    cidades = Cidade.objects.all()
    return render_to_response('paginas/termos.html', {
                'cidades' : cidades,
              }, context_instance=RequestContext( request ) )

def faq(request):
    cidades = Cidade.objects.all()
    return render_to_response('paginas/faq.html', {
                  'cidades' : cidades,
              }, context_instance=RequestContext( request ) )

def howitworks(request):
    cidades = Cidade.objects.all()
    return render_to_response('paginas/howitworks.html', {
                  'cidades' : cidades,
              }, context_instance=RequestContext( request ) )

def sobre(request):
    cidades = Cidade.objects.all()
    return render_to_response('paginas/sobre.html', {
                  'cidades' : cidades,
              }, context_instance=RequestContext( request ) )


def contato(request):
    cidades = Cidade.objects.all()
    return render_to_response('paginas/contato.html', {
                  'cidades' : cidades,
              }, context_instance=RequestContext( request ) )


def cidade_index(request, cidade_slug):
    cidade = Cidade.objects.get(slug=cidade_slug)
    cidades_disponiveis = Cidade.objects.all()
    ofertas = Oferta.objects.filter(ativo=True)
    destaque = Oferta.objects.filter(cidade=cidade,destaque=True,ativo=True)
    #geoprocessamento
    ip_address=request.META.get('REMOTE_ADDR') 
    g = GeoIP()
    #local_full_cliente = g.city(ip_address)
    local_full_cliente = g.city('201.22.164.216')
    cidade_cliente = local_full_cliente.get('city')
   
    print(cidade_cliente)

    if ofertas:
        try:
            oferta_estreia = ofertas.filter(estreando=True)[0]
        except IndexError:
            oferta_estreia = ofertas[0]

        outras_ofertas = ofertas.exclude(pk=oferta_estreia.pk)
    else:
        oferta_estreia = None
        outras_ofertas = []
    
    return render_to_response('index.html',locals(),context_instance=RequestContext(request),)

def buscar(request):
    form = FormBuscar()
    bookmarks = []
    show_results = False
    if 'query' in request.GET:
        show_results = True
        query = request.GET['query'].strip()
        if query:
            form = FormBuscar({'query' : query})#Usado para manter o valor do campo no formulario quando atualizar
            ofertas = Oferta.objects.filter(
            titulo__icontains=query
            )[:10]
    variables = RequestContext(request, {
    'form': form,
    'bookmarks': bookmarks,
    'show_results': show_results,
    'show_tags': True,
    'show_user': True
    })
    if request.GET.has_key('ajax'):
        #print variables
        return render_to_response('index.html', variables)
    else:
        #print variables
        return render_to_response('buscar.html', variables)

def inscricao_cidade(request, cidade_slug):
    try:
        cidade = Cidade.objects.get(slug=cidade_slug)
    except:
        return HttpResponseRedirect('/ofertas/groupon-clone/')


    if request.method == 'POST': # If the form has been submitted...
        form = EmailInscForm(request.POST)

        if form.is_valid():
            cd = form.cleaned_data

            form = EmailInscricao()
            form.email = cd.get('email')
            e_cidade = Cidade.objects.get(id = int(cd.get('cidade')))
            form.cidade = e_cidade
            form.save()

            user_msg = "Obrigado por se cadastrar!"
            user_msg = quote(user_msg)
            return HttpResponseRedirect('/?user_msg=' + user_msg)

          # set some sort of message and redirect back to deals

    else:
        initial_data = { 'cidade': cidade.id }
        form = EmailInscForm(initial=initial_data)

    cidades = Cidade.objects.all()

    return render_to_response('cabecalho.html', {
                'cidade' : cidade,
                'form' : form,
                'cidades' : cidades,
              }, context_instance=RequestContext( request ) )


@login_required
def profile(request):
    cidades = Cidade.objects.all()
    cupons = Cupon.objects.filter(user = request.user, status=STATUS_ATIVO)

#@login_required  # unlock to make fb work!!
def index(request):
    return HttpResponseRedirect(settings.DEFAULT_CITY_SLUG)


def oferta_checkout_complete(request, cidade_slug, oferta_pk, quantidade):
    user_msg = ""
    quantidade = int(quantidade)

    oferta = get_object_or_404(Oferta, pk=oferta_pk)

    token = request.GET.get('token', None)
    payerid = request.GET.get('PayerID', None)

#    if token and payerid:
#
#        # TODO: i have no idea how many they bought!
#        p = PayPal()
#        rc = p.DoExpressCheckoutPayment("CAD", quantidade * oferta.preco_oferta, token, payerid, PAYMENTACTION="Authorization")
#
#        if rc:  # payment is looking good
#            response = PayPalResponse()
#            response.fill_from_response(p.GetPaymentResponse())
#            response.status = PayPalResponse.get_default_status()
#            response.save()
#
#            num_oferta_vendidas = oferta.num_vendido()
#
#            # check if it's sold out!
#            if num_oferta_vendidas > oferta.qtd_ofertas_disponiveis:
#                pass
#                #setup form error
#                # Sold out!
#
#            for i in range(quantidade):
#                cupon = Cupon()
#                cupon.user = request.user
#                cupon.oferta = oferta
#
#                cupon.status = STATUS_EMESPERA
#
#                cupon.save()
#                num_oferta_vendidas = num_oferta_vendidas + 1
#
#                # update the deal object 
#                if not oferta.ativo and num_oferta_vendidas >= oferta.qtd_fechamento:
#                  oferta.data_fechamento = datetime.datetime.now()
#                  oferta.ativo = True
#                  oferta.save()
#
#            user_msg = 'Obrigado por comprar dentro de 24 horas seu cupon sera liberado'
#            return HttpResponseRedirect('/ofertas/groupon-clone/?user_msg=' + user_msg )
        
    raise Http404()


def oferta_checkout(request, cidade_slug, oferta_slug):
    user_msg = ""
    try:
        oferta = Oferta.objects.get(slug=oferta_slug)
    except:
        return HttpResponseRedirect('/')

    must_login_error = False
    must_login_email = None
    maximo = oferta.qtd_ofertas_por_pessoa # maxima quantidade para cada cliente
    maximo = list(range(1,maximo+1))       # transforma essa quantidade numa lista
    lista = [(str(i), i) for i in maximo]  # transforma numa lista de dicionarios
    
    if request.method == 'POST': # If the form has been submitted...
        form = OfertaCheckoutForm(request.POST,lista=lista)

        # Se o usuario nao estiver autenticado
        if not request.user.is_authenticated():
            try:
                user = User.objects.get(email=request.POST['email'])
                must_login_error = True
                must_login_email = request.POST['email']
                form = OfertaCheckoutForm(lista=lista)
                user_msg = 'A conta existe: ' + user.email  + '. Efetue Login.'
            except:
                #return HttpResponseRedirect('/')
                pass
                
        else:
            user = request.user
#Se native erro no formulario e o formulario for valido 
        #if not must_login_error and form.is_valid():
        if form.is_valid():
            cd = form.cleaned_data

            if not request.user.is_authenticated():
                # User in NOT Logged IN and doesn't exist
                # setup a new user
                user = User()
                user.username = cd.get('email')  #str(uuid.uuid4())[:30]
                user.first_name = cd.get('nome_completo')
                user.email = cd.get('email')
                user.save()
                user.set_password( cd.get('senha') )
                user.save()


                user = authenticate(username=user.username, password=cd.get('senha'))
                if user is not None:
                    if user.is_active:
                        login(request, user)
                        # Redirect to a success page.
                    else:
                        pass
                        # Return a 'disabled account' error message
                else:
                    # Return an 'invalid login' error message.
                    pass

            quantidade = int(cd.get('quantidade'))#pega o conteudo pelo nome do elemento dom
            preco_total = quantidade * oferta.preco_oferta

#            p = PayPal()
#            rc = p.SetExpressCheckout(preco_total, "CAD", "http://www.massivecoupon.com/deals/" + oferta.slug + "/" + str(quantidade) + "/checkout/complete/", "http://www.massivecoupon.com/", PAYMENTACTION="Authorization")
#
#            if rc:
#                token = p.api_response['TOKEN'][0]
#                return HttpResponseRedirect( p.paypal_url() )
#            else:
#                return HttpResponseRedirect('/checkout/error') 
     
    else:
        form = OfertaCheckoutForm(lista=lista)

    cidades = Cidade.objects.all()

    return render_to_response('oferta/oferta_checkout.html', {
                'form' : form,
                'oferta' : oferta,
                'user_msg' : user_msg,
                'must_login_error' : must_login_error,
                'must_login_email' : must_login_email,
                'cidades' : cidades,
              }, context_instance=RequestContext( request ) )


#Definicao do mapa
class MapForm(forms.Form):
    map = forms.Field(widget=GoogleMap(attrs={'width':410, 'height':410}))

def oferta_detalhe(request, cidade_slug, oferta_slug):
    cidade = Cidade.objects.get(slug=cidade_slug)
    cidades_disponiveis = Cidade.objects.all()
    try:
        user_msg = request.GET.get('user_msg', None)
    except:
        user_msg = None

    oferta = get_object_or_404(Oferta, slug=oferta_slug)

    if not oferta.esta_expirado(): 
        tempo_restante = oferta.publicado_em.strftime("%d,%m,%Y") #+ ' 11:59 PM'
    else:
        tempo_restante = -1
    
    #Mapa
    
    gmap = maps.Map(opts = {
        'center': maps.LatLng(oferta.latitude, oferta.longitude),
        'mapTypeId': maps.MapTypeId.ROADMAP,
        'zoom': 15,
        'mapTypeControlOptions': {
             'style': maps.MapTypeControlStyle.DROPDOWN_MENU
             #'style': maps.MapTypeControlStyle
        },
    })
    marker = maps.Marker(opts = {
        'map': gmap,

        'position': maps.LatLng(oferta.latitude, oferta.longitude),
    })
    maps.event.addListener(marker, 'mouseover', 'myobj.markerOver')
    maps.event.addListener(marker, 'mouseout', 'myobj.markerOut')
    info = maps.InfoWindow({
        'content': '<h3>'+oferta.anunciante.nome+'</h3>'+
                   '<p>Rua: '+oferta.anunciante.endereco+'</p>'+
                   '<p>Telefone: '+oferta.anunciante.telefone+'</p>',
        'disableAutoPan': False
    })
    info.open(gmap, marker)
    context = {'form': MapForm(initial={'map': gmap}),
               'user_msg' : user_msg,
                'oferta' : oferta,
                'tempo_restante' : tempo_restante,
                'cidades_disponiveis': cidades_disponiveis,}
    
    return render_to_response('oferta_detalhes.html', context)
#    return render_to_response('oferta_detalhes.html', {
#               # 'now' : now,
#                'user_msg' : user_msg,
#                'oferta' : oferta,
#                'tempo_restante' : tempo_restante,
#              }, context_instance=RequestContext( request ) )


