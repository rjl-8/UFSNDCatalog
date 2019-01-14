# UdacityCatalog

This code is intended to satisfy the requirements of the Catalog project in the Programming Fundamentals lesson of the Full Stack Web Developer nanodegree.

### Prerequisites

* Install python 2.7.x
* Install Postgresql
* get project starter from [github] (https://github.com/udacity/fullstack-nanodegree-vm) (this includes Vagrant)
* Create the database for the project by typing the following in the terminal
* Have at least one Google account

```
cd (vagrant folder)
vagrant up
vagrant ssh
sudo passwd postgres
su postgres
psql
create role catalog with login password '******';
create database catalog with owner=catalog;
\q
```

## Built With

* [Python](http://python.org/) - The programming language used
* [Postgresql](http://postgresql.org) - The database used
* [Vagrant](https://pythondata.com/vagrant-on-windows/) - the unix terminal emulator

## Authors

* **Ron Lewis** - *Initial work* - [rjl-8](https://github.com/rjl-8)

## Usage

run the python file to create the tables and initial dataset:
```
python database_setup.py
```
then run the python file for the webserver:
```
python webserver.py
```

and then browse to http://localhost:5000/

## Acknowledgments

* Hat tip to Udacity for forcing me to learn all this cool stuff