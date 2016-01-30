from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))

class ShoppingList(Base):
    __tablename__ = 'shoppinglist'
   
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)    
    shared_email = Column(String(250), nullable=True)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User) 

    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'name'         : self.name,
           'id'           : self.id
       }
 
class Item(Base):
    __tablename__ = 'item'

    name =Column(String(80), nullable = False)
    id = Column(Integer, primary_key = True)
    quantity = Column(String(8))
    shoppinglist_id = Column(Integer,ForeignKey('shoppinglist.id'))
    shoppinglist = relationship(ShoppingList)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'name'         : self.name,
           'id'           : self.id,
           'quantity'     : self.quantity
       }
engine = create_engine('sqlite:///shoppinglistitemwithusers.db') 

Base.metadata.create_all(engine)