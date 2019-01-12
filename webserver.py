from flask import Flask, render_template, request, redirect, url_for, jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Job, Tool

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
from flask import make_response
import requests

import json

#??need to import HTTPBasicAuth
#auth = HTTPBasicAuth()
app = Flask(__name__)

engine = create_engine('sqlite:///jobtools.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

#id for oauth
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

# oAuth and User parts of website
#################################
a='''
@auth.verify_password
def verify_password(username_or_token, password):
    #Try to see if it's a token first
    user_id = User.verify_auth_token(username_or_token)
    if user_id:
        user = session.query(User).filter_by(id = user_id).one()
    else:
        user = session.query(User).filter_by(username = username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

@app.route('/clientOAuth')
def start():
    return render_template('clientOAuth.html')

@app.route('/oauth/<provider>', methods = ['POST'])
def login(provider):
    #STEP 1 - Parse the auth code
    auth_code = request.json.get('auth_code')
    print "Step 1 - Complete, received auth code %s" % auth_code
    if provider == 'google':
        #STEP 2 - Exchange for a token
        try:
            # Upgrade the authorization code into a credentials object
            oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchange(auth_code)
        except FlowExchangeError:
            response = make_response(json.dumps('Failed to upgrade the authorization code.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response
          
        # Check that the access token is valid.
        access_token = credentials.access_token
        url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
        h = httplib2.Http()
        result = json.loads(h.request(url, 'GET')[1])
        # If there was an error in the access token info, abort.
        if result.get('error') is not None:
            response = make_response(json.dumps(result.get('error')), 500)
            response.headers['Content-Type'] = 'application/json'
            
        # # Verify that the access token is used for the intended user.
        # gplus_id = credentials.id_token['sub']
        # if result['user_id'] != gplus_id:
        #     response = make_response(json.dumps("Token's user ID doesn't match given user ID."), 401)
        #     response.headers['Content-Type'] = 'application/json'
        #     return response

        # # Verify that the access token is valid for this app.
        # if result['issued_to'] != CLIENT_ID:
        #     response = make_response(json.dumps("Token's client ID does not match app's."), 401)
        #     response.headers['Content-Type'] = 'application/json'
        #     return response

        # stored_credentials = login_session.get('credentials')
        # stored_gplus_id = login_session.get('gplus_id')
        # if stored_credentials is not None and gplus_id == stored_gplus_id:
        #     response = make_response(json.dumps('Current user is already connected.'), 200)
        #     response.headers['Content-Type'] = 'application/json'
        #     return response
        print "Step 2 Complete! Access Token : %s " % credentials.access_token

        #STEP 3 - Find User or make a new one
        
        #Get user info
        h = httplib2.Http()
        userinfo_url =  "https://www.googleapis.com/oauth2/v1/userinfo"
        params = {'access_token': credentials.access_token, 'alt':'json'}
        answer = requests.get(userinfo_url, params=params)
      
        data = answer.json()

        name = data['name']
        picture = data['picture']
        email = data['email']
        
        
     
        #see if user exists, if it doesn't make a new one
        user = session.query(User).filter_by(email=email).first()
        if not user:
            user = User(username = name, picture = picture, email = email)
            session.add(user)
            session.commit()

        

        #STEP 4 - Make token
        token = user.generate_auth_token(600)

        

        #STEP 5 - Send back token to the client 
        return jsonify({'token': token.decode('ascii')})
        
        #return jsonify({'token': token.decode('ascii'), 'duration': 600})
    else:
        return 'Unrecoginized Provider'

@app.route('/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})



@app.route('/users', methods = ['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        print "missing arguments"
        abort(400) 
        
    if session.query(User).filter_by(username = username).first() is not None:
        print "existing user"
        user = session.query(User).filter_by(username=username).first()
        return jsonify({'message':'user already exists'}), 200#, {'Location': url_for('get_user', id = user.id, _external = True)}
        
    user = User(username = username)
    user.hash_password(password)
    session.add(user)
    session.commit()
    return jsonify({ 'username': user.username }), 201#, {'Location': url_for('get_user', id = user.id, _external = True)}

@app.route('/api/users/<int:id>')
def get_user(id):
    user = session.query(User).filter_by(id=id).one()
    if not user:
        abort(400)
    return jsonify({'username': user.username})

@app.route('/api/resource')
@auth.login_required
def get_resource():
    return jsonify({ 'data': 'Hello, %s!' % g.user.username })
'''
# end oAuth and User parts of website
#####################################


# Data part of website
######################
prev_loc = ''

# home - list of jobs and most recent tools
@app.route('/')
def home():
    prev_loc = 'home'
    retval = render_template('header.html')
    retval += 'not logged in: list of jobs and the most recently added tools'
    retval += '<br/>logged in: add "Add Item" link'

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

    retval += render_template('home.html', jobs=jobs, recenttools=recenttools)
    retval += render_template('footer.html')
    return retval


# list of tools for a selected job
@app.route('/catalog/<string:job_name>/tools')
def getToolsForJob(job_name):
    prev_loc = 'getToolsForJob'
    retval = render_template('header.html')
    retval += 'not logged in: list of jobs and list of tools for the selected job (highlight selection)'
    retval += '<br/>logged in: ??'

    # get list of jobs
    jobs = session.query(Job).all()

    # get list of tools for selected job and associated count
    tools = session.query(Tool).join(Job).filter(Job.name==job_name)
    toolcount=0
    for tool in tools:
        toolcount += 1

    retval += render_template('tools.html', toolcount=toolcount, job_name=job_name, jobs=jobs, tools=tools)
    retval += render_template('footer.html')
    return retval


# description for a selected tool
@app.route('/catalog/<string:job_name>/<string:tool_name>')
def getToolDescription(job_name, tool_name):
    prev_loc = 'getToolDescription'
    retval = render_template('header.html')
    retval += 'not logged in: just a description of the tool'
    retval += '<br/>logged in: add edit/delete links'

    # get info for selected tool
    tool = session.query(Tool).join(Job).filter(Job.name==job_name).filter(Tool.name==tool_name)

    retval += render_template('tooldesc.html', tool=tool, job_name=job_name)
    retval += render_template('footer.html')
    return retval


# form to edit tool and the processing thereof
@app.route('/catalog/<string:job_name>/<string:tool_name>/edit', methods=['GET', 'POST'])
def getToolEdit(job_name, tool_name):
    # get info for selected tool
    tool = session.query(Tool).join(Job).filter(Job.name==job_name).filter(Tool.name==tool_name)

    if request.method == 'POST':
        if request.form['inp_tool_name']:
            tool.name = request.form['inp_tool_name']
        if request.form['inp_tool_desc']:
            tool.description = request.form['inp_tool_desc']
        if request.form['sel_job_name']:
            tool.job_id = session.query(Job).filter(Job.name==request.form['sel_job_name']).one().id

        return redirect(url_for(prev_loc))
    else:
        retval = render_template('header.html')
        retval += 'not logged in: deny access message - provide link to login'
        retval += '<br/>logged in: edit tool form'

        # get list of jobs
        jobs = session.query(Job).all()

        retval += render_template('tooledit.html', tool=tool, jobs=jobs, job_name=job_name)
        retval += render_template('footer.html')
        return retval
        

# form to delete a tool and the processing thereof
@app.route('/catalog/<string:tool_name>/delete', methods=['GET', 'POST'])
def getToolDelete(tool_name):
    if request.method == 'POST':
        return redirect(url_for(prev_loc))
    else:
        retval = render_template('header.html')
        retval += 'not logged in: deny access message - provide link to login'
        retval += '<br/>logged in: delete tool confirmation form'
        retval += render_template('footer.html')
        return retval


# json service for db dump
@app.route('/catalog.json')
def getJson():
    retval = 'not logged in: json dump of database'
    retval += '<br/>logged in: same'
    jobs = session.query(Job).all()
    retval += jsonify(Jobs=[job.serialize for job in jobs])
    tools = session.query(Tool).all()
    retval += jsonify(Tools=[tool.serialize for tool in tools])
    return retval



###EXAMPLE###
#############
@app.route('/')
@app.route('/restaurants/<int:restaurant_id>/')
def restaurantMenu(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    items = session.query(MenuItem).filter_by(restaurant_id=restaurant.id)
    return render_template('menu.html', restaurant=restaurant, items=items)

    # example of raw sql with parameter
    #result = session.execute('SELECT * FROM tool WHERE my_column = :val', {'val': 5})

if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)