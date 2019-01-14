from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, g
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Job, Tool, User

from flask import session as login_session

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
from flask import make_response
import requests

import random
import string

import json

app = Flask(__name__)

#engine = create_engine('sqlite:///jobtools.db')
engine = create_engine('postgresql://catalog:Passw0rd@localhost:5432/catalog')

Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

#id for oauth
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Repair Job Tools Application"


# oAuth and User parts of website
#################################
# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange we have to
        split the token first on commas and select the first index which gives us the key : value
        for the server access token then we split it on colons to pull out the actual token value
        and replace the remaining quotes with nothing so that it can be used directly in the graph
        api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()
    print data
    login_session['username'] = data['email']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        flash('Successfully disconnected.')
    else:
        flash('Clumsy disconnect.')
        flash(result['status'])
    login_session['access_token'] = None
    return redirect(url_for('home'))


# User Helper Functions
def createUser(login_session):
    newUser = User(username=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# end oAuth and User parts of website
#####################################

# Data part of website
######################
def getHeader():
    print login_session.get('access_token')
    if login_session.get('access_token') is not None:
        logged_in = True
    else:
        logged_in = False

    provider = login_session.get('provider')

    html = render_template('header.html', **locals())

    return logged_in, provider, html


# home - list of jobs and most recent tools
@app.route('/')
def home():
    logged_in, provider, retval = getHeader()

    # get list of jobs
    jobs = session.query(Job).all()

    # get list of recently added tools
    #recenttools = session.query(Tool).all()
    sql = '''\
    SELECT tool.name, tool.date_added, job.name AS job_name
    FROM tool
         JOIN (
               SELECT job_id, MAX(date_added) max_date_added
               FROM tool
               GROUP BY job_id
              ) last_tool
            ON tool.job_id = last_tool.job_id
            AND tool.date_added = max_date_added
         JOIN job
            ON tool.job_id = job.id
    '''
    recenttools = session.execute(sql)

    retval += render_template('home.html', **locals())
    retval += render_template('footer.html')
    return retval


# list of tools for a selected job
@app.route('/catalog/<string:job_name>/tools')
def getToolsForJob(job_name):
    logged_in, provider, retval = getHeader()

    # get list of jobs
    jobs = session.query(Job).all()

    # get list of tools for selected job and associated count
    tools = session.query(Tool).join(Job).filter(Job.name==job_name)
    toolcount=0
    for tool in tools:
        toolcount += 1

    retval += render_template('tools.html', **locals())
    retval += render_template('footer.html')
    return retval


# description for a selected tool
@app.route('/catalog/<string:job_name>/<string:tool_name>')
def getToolDescription(job_name, tool_name):
    logged_in, provider, retval = getHeader()

    # get info for selected tool
    tool = session.query(Tool).join(Job).filter(Job.name==job_name).filter(Tool.name==tool_name)

    retval += render_template('tooldesc.html', **locals())
    retval += render_template('footer.html')
    return retval


# Create a new tool
@app.route('/catalog/newtool/', methods=['GET', 'POST'])
def newTool():
    if request.method == 'POST':
        print 'inp_tool_name = ' + request.form['inp_tool_name']
        print 'inp_tool_desc = ' + request.form['inp_tool_desc']
        print 'sel_job_name = ' + request.form['sel_job_name']
        if request.form['inp_tool_name'] and request.form['inp_tool_desc'] and request.form['sel_job_name']:
            newTool = Tool(name=request.form['inp_tool_name'], 
                           description=request.form['inp_tool_desc'],
                           job_id=session.query(Job).filter(Job.name==request.form['sel_job_name']).one().id,
                           owner='g.user_id')
            session.add(newTool)
            session.commit()
            flash('New tool added!')
        else:
            flash('ERROR: You must input a name and description and select a job for the tool')

        return redirect(url_for('home'))
    else:
        logged_in, provider, retval = getHeader()

        # get empty tool object to be able to reuse tooledit.html
        tool = session.query(Tool).filter(Tool.name=='')

        # get list of jobs
        jobs = session.query(Job).all()

        retval += render_template('tooledit.html', tool=tool, jobs=jobs, job_name='')
        retval += render_template('footer.html')
        return retval


# form to edit tool and the processing thereof
@app.route('/catalog/<string:job_name>/<string:tool_name>/edit', methods=['GET', 'POST'])
def getToolEdit(job_name, tool_name):
    # get info for selected tool
    tool = session.query(Tool).join(Job).filter(Job.name==job_name).filter(Tool.name==tool_name).one()
    if request.method == 'POST':
        if request.form['inp_tool_name']:
            print 'updated name'
            tool.name = request.form['inp_tool_name']
        if request.form['inp_tool_desc']:
            print 'updated description'
            tool.description = request.form['inp_tool_desc']
        if request.form['sel_job_name']:
            print 'update job'
            tool.job_id = session.query(Job).filter(Job.name==request.form['sel_job_name']).one().id

        flash('Tool successfully edited!')
        return redirect(url_for('home'))
    else:
        logged_in, provider, retval = getHeader()

        # get list of jobs
        jobs = session.query(Job).all()
        retval += render_template('tooledit.html', **locals())
        retval += render_template('footer.html')
        return retval
        

# form to delete a tool and the processing thereof
@app.route('/catalog/<string:job_name>/<string:tool_name>/delete', methods=['GET', 'POST'])
def getToolDelete(job_name, tool_name):
    # get info for selected tool
    tool = session.query(Tool).join(Job).filter(Job.name==job_name).filter(Tool.name==tool_name).one()

    if request.method == 'POST':
        # do delete
        session.delete(tool)
        session.commit()
        flash('You nasty devil you, deleting data!')
        return redirect(url_for('home'))
    else:
        logged_in, provider, retval = getHeader()
        retval += render_template('tooldelete.html', **locals())
        retval += render_template('footer.html')
        return retval


# json services for db dump
@app.route('/catalog/jobs.json')
def getJobsJson():
    jobs = session.query(Job).all()
    retval = jsonify(Jobs=[job.serialize for job in jobs])
    return retval


@app.route('/catalog/tools.json')
def getToolsJson():
    tools = session.query(Tool).all()
    retval = jsonify(Tools=[tool.serialize for tool in tools])
    return retval


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)