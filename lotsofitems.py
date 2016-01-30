from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import ShoppingList, Base, Item, User

engine = create_engine('sqlite:///shoppinglistitemwithusers.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

# Create dummy user
User1 = User(name="Lakshmi S Nair", email="laxmi256@gmail.com", picture='https://lh3.googleusercontent.com/-X_99w-tbVxk/AAAAAAAAAAI/AAAAAAAAKo4/wEqfD6cBWLM/s96-c/photo.jpg')
session.add(User1)
session.commit()

shoppinglist1 = ShoppingList(user_id=1, name="Big Bazaar List", shared_email="laxmi256@gmail.com")
session.add(shoppinglist1)
session.commit()


item1 = Item(user_id=1, name="Rice", quantity="20kg", shoppinglist=shoppinglist1)
session.add(item1)
session.commit()

item2 = Item(user_id=1, name="Idli Rice", quantity="5kg", shoppinglist=shoppinglist1)
session.add(item2)
session.commit()

item3 = Item(user_id=1, name="Dosa Rice", quantity="5kg", shoppinglist=shoppinglist1)
session.add(item3)
session.commit()

item4 = Item(user_id=1, name="Sugar", quantity="5kg", shoppinglist=shoppinglist1)
session.add(item4)
session.commit()

item5 = Item(user_id=1, name="Atta", quantity="2kg", shoppinglist=shoppinglist1)
session.add(item5)
session.commit()

item6 = Item(user_id=1, name="Tea powder", quantity="1/2kg", shoppinglist=shoppinglist1)
session.add(item6)
session.commit()

item7 = Item(user_id=1, name="Urad Daal", quantity="1kg", shoppinglist=shoppinglist1)
session.add(item7)
session.commit()

item8 = Item(user_id=1, name="Toor Daal", quantity="1/2kg", shoppinglist=shoppinglist1)
session.add(item8)
session.commit()

print "Added One User and its Shopping List!"