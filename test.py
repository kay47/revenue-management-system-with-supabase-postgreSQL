from app import app, db, Product

with app.app_context():
    Product.query.delete()
    db.session.commit()
    print("✅ All products deleted successfully!")
    print(Product.query.count())


