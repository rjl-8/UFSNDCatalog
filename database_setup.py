import os
import sys
import datetime
from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

Base = declarative_base()


class Job(Base):
    __tablename__ = 'job'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    owner = Column(String(100), nullable=False)
    date_added = Column(DateTime, default=datetime.datetime.now)

# We added this serialize function to be able to send JSON objects in a
# serializable format
    @property
    def serialize(self):

        return {
            'name': self.name,
            'id': self.id,
            'owner': self.owner
        }


class Tool(Base):
    __tablename__ = 'tool'

    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    description = Column(String(250))
    owner = Column(String(100), nullable=False)
    date_added = Column(DateTime, default=datetime.datetime.now)
    job_id = Column(Integer, ForeignKey('job.id'))
    job = relationship(Job)

# We added this serialize function to be able to send JSON objects in a
# serializable format
    @property
    def serialize(self):

        return {
            'name': self.name,
            'description': self.description,
            'id': self.id,
            'job_id': self.job_id,
            'owner': self.owner
        }


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True)
    picture = Column(String)
    email = Column(String)
    password_hash = Column(String(64))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
    	s = Serializer(secret_key, expires_in = expiration)
    	return s.dumps({'id': self.id })

    @staticmethod
    def verify_auth_token(token):
    	s = Serializer(secret_key)
    	try:
    		data = s.loads(token)
    	except SignatureExpired:
    		#Valid Token, but expired
    		return None
    	except BadSignature:
    		#Invalid Token
    		return None
    	user_id = data['id']
    	return user_id


engine = create_engine('sqlite:///jobtools.db')
#engine = create_engine('postgresql://student:letmein@localhost:5432/mydatabase')


Base.metadata.create_all(engine)

#data try1
#conn = engine.connect()
#ins = Job.insert().values(name='Plumber', owner='default')
#ins.compile().params
#result = conn.execute(ins)

#data try2
DBSession = sessionmaker(bind=engine)
session = DBSession()

newJob = Job(name='Electrician', owner='default')
session.add(newItem)
newJob = Job(name='Plumber', owner='default')
session.add(newItem)
newJob = Job(name='Carpenter', owner='default')
session.add(newItem)
newJob = Job(name='Mason', owner='default')
session.add(newItem)
newJob = Job(name='Roofer', owner='default')
session.add(newItem)
newJob = Job(name='Gardener', owner='default')
session.add(newItem)
newJob = Job(name='Landscaper', owner='default')
session.add(newItem)

session.commit()

job = session.query(Job).filter_by(name='Electrician').one()
newTool = Tool(name='Wire Cutters', job_id = job.id, description='A tool that cuts wires', owner='default')
session.add(newTool)
newTool = Tool(name='Meter', job_id = job.id, description='A tool that cuts wires', owner='default')
session.add(newTool)
job = session.query(Job).filter_by(name='Plumber').one()
newTool = Tool(name='Wrench', job_id = job.id, description='A tool that cuts wires', owner='default')
session.add(newTool)
newTool = Tool(name='Plumbers Tape', job_id = job.id, description='A tool that cuts wires', owner='default')
session.add(newTool)
job = session.query(Job).filter_by(name='Carpenter').one()
newTool = Tool(name='Hammer', job_id = job.id, description='A tool that cuts wires', owner='default')
session.add(newTool)
newTool = Tool(name='Hammer', job_id = job.id, description='A tool that cuts wires', owner='default')
session.add(newTool)
newTool = Tool(name='Measuring Tape', job_id = job.id, description='A tool that cuts wires', owner='default')
session.add(newTool)
job = session.query(Job).filter_by(name='Mason').one()
newTool = Tool(name='Cement Mixer', job_id = job.id, description='A tool that cuts wires', owner='default')
session.add(newTool)
newTool = Tool(name='Trowel', job_id = job.id, description='A tool that cuts wires', owner='default')
session.add(newTool)
job = session.query(Job).filter_by(name='Roofer').one()
newTool = Tool(name='Hammer', job_id = job.id, description='A tool that cuts wires', owner='default')
session.add(newTool)
newTool = Tool(name='Ladder', job_id = job.id, description='A tool that cuts wires', owner='default')
session.add(newTool)
job = session.query(Job).filter_by(name='Gardener').one()
newTool = Tool(name='Hoe', job_id = job.id, description='A tool that cuts wires', owner='default')
session.add(newTool)
newTool = Tool(name='Shovel', job_id = job.id, description='A tool that cuts wires', owner='default')
session.add(newTool)
job = session.query(Job).filter_by(name='Landscaper').one()
newTool = Tool(name='Shovel', job_id = job.id, description='A tool that cuts wires', owner='default')
session.add(newTool)
newTool = Tool(name='Lawnmower', job_id = job.id, description='A tool that cuts wires', owner='default')
session.add(newTool)
newTool = Tool(name='Weedeater', job_id = job.id, description='A tool that cuts wires', owner='default')
session.add(newTool)

session.commit()
