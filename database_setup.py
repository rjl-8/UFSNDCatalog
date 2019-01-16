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
        s = Serializer(secret_key, expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(secret_key)
        try:
            data = s.loads(token)
        except SignatureExpired:
            # Valid Token, but expired
            return None
        except BadSignature:
            # Invalid Token
            return None
        user_id = data['id']
        return user_id


# engine = create_engine('sqlite:///jobtools.db')
engine = create_engine('postgresql://catalog:Passw0rd@localhost:5432/catalog')


Base.metadata.create_all(engine)

# data
if __name__ == '__main__':
    DBSession = sessionmaker(bind=engine)
    session = DBSession()

    # clean tables
    tools = session.query(Tool)
    for tool in tools:
        session.delete(tool)
    jobs = session.query(Job)
    for job in jobs:
        session.delete(job)
    users = session.query(User)
    for user in users:
        session.delete(user)

    session.commit()

    newJob = Job(name='Electrician', owner='rondevwork@gmail.com')
    session.add(newJob)
    newJob = Job(name='Plumber', owner='rondevwork@gmail.com')
    session.add(newJob)
    newJob = Job(name='Carpenter', owner='rondevwork@gmail.com')
    session.add(newJob)
    newJob = Job(name='Mason', owner='rondevwork@gmail.com')
    session.add(newJob)
    newJob = Job(name='Roofer', owner='rondevwork@gmail.com')
    session.add(newJob)
    newJob = Job(name='Gardener', owner='rondevwork@gmail.com')
    session.add(newJob)
    newJob = Job(name='Landscaper', owner='rondevwork@gmail.com')
    session.add(newJob)
    newJob = Job(name='Welder', owner='rlewis8@gmail.com')
    session.add(newJob)

    session.commit()

    job = session.query(Job).filter_by(name='Electrician').one()
    desc = 'A tool that cuts wires.  It usually has features '
    desc += 'allowing the stripping and trimming of wires as well.'
    newTool = Tool(name='Wire Cutters',
                   job_id=job.id,
                   description=desc,
                   owner='rondevwork@gmail.com')
    session.add(newTool)
    desc = 'This tool allows the measuring of voltages '
    desc += 'and amps in a given circuit.'
    newTool = Tool(name='Meter',
                   job_id=job.id,
                   description=desc,
                   owner='rondevwork@gmail.com')
    session.add(newTool)

    job = session.query(Job).filter_by(name='Plumber').one()
    desc = 'A tool that can be used to loosen or tighten nuts or '
    desc += 'bolts or any threaded connector.'
    newTool = Tool(name='Wrench',
                   job_id=job.id,
                   description=desc,
                   owner='rondevwork@gmail.com')
    session.add(newTool)
    desc = 'Tape used to make threaded connections water tight.'
    newTool = Tool(name='Plumbers Tape',
                   job_id=job.id,
                   description=desc,
                   owner='rondevwork@gmail.com')
    session.add(newTool)

    job = session.query(Job).filter_by(name='Carpenter').one()
    desc = 'A tool for defeating Thanos.'
    newTool = Tool(name='Hammer',
                   job_id=job.id,
                   description=desc,
                   owner='rondevwork@gmail.com')
    session.add(newTool)
    desc = 'A tool used to measure distances.  Often used to measure '
    desc += 'lengths for boards used to build things.'
    newTool = Tool(name='Measuring Tape',
                   job_id=job.id,
                   description=desc,
                   owner='rondevwork@gmail.com')
    session.add(newTool)

    job = session.query(Job).filter_by(name='Mason').one()
    desc = 'A device used to mix the ingredients of cement together.'
    newTool = Tool(name='Cement Mixer',
                   job_id=job.id,
                   description=desc,
                   owner='rondevwork@gmail.com')
    session.add(newTool)
    desc = 'A tool that spreads mortar for bricks or tile.'
    newTool = Tool(name='Trowel',
                   job_id=job.id,
                   description=desc,
                   owner='rondevwork@gmail.com')
    session.add(newTool)

    job = session.query(Job).filter_by(name='Roofer').one()
    desc = 'A tool for defeating Thanos but used by a roofer.'
    newTool = Tool(name='Hammer',
                   job_id=job.id,
                   description=desc,
                   owner='rondevwork@gmail.com')
    session.add(newTool)
    desc = 'A tool allows the user to climb to altitudes unreachable '
    desc += 'by other means.'
    newTool = Tool(name='Ladder',
                   job_id=job.id,
                   description=desc,
                   owner='rondevwork@gmail.com')
    session.add(newTool)

    job = session.query(Job).filter_by(name='Gardener').one()
    desc = 'A tool for digging in the dirt in a line.'
    newTool = Tool(name='Hoe',
                   job_id=job.id,
                   description=desc,
                   owner='rondevwork@gmail.com')
    session.add(newTool)
    desc = 'A tool for digging in the dirt.'
    newTool = Tool(name='Shovel',
                   job_id=job.id,
                   description=desc,
                   owner='rlewis8@gmail.com')
    session.add(newTool)

    job = session.query(Job).filter_by(name='Landscaper').one()
    desc = 'A tool for digging in the dirt.'
    newTool = Tool(name='Shovel',
                   job_id=job.id,
                   description=desc,
                   owner='rlewis8@gmail.com')
    session.add(newTool)
    desc = 'A tool that cuts grass.'
    newTool = Tool(name='Lawnmower',
                   job_id=job.id,
                   description=desc,
                   owner='rlewis8@gmail.com')
    session.add(newTool)
    desc = 'A tool that cuts weeds in places a lawnmower cannot reach.'
    newTool = Tool(name='Weedeater',
                   job_id=job.id,
                   description=desc,
                   owner='rlewis8@gmail.com')
    session.add(newTool)

    job = session.query(Job).filter_by(name='Welder').one()
    desc = 'A device that covers the face for protection during welding.'
    newTool = Tool(name='Mask',
                   job_id=job.id,
                   description=desc,
                   owner='rlewis8@gmail.com')
    session.add(newTool)
    desc = 'A tool that melts metal.'
    newTool = Tool(name='Torch',
                   job_id=job.id,
                   description=desc,
                   owner='rlewis8@gmail.com')
    session.add(newTool)

    session.commit()
