from fastapi import FastAPI
from strawberry.asgi import GraphQL
from app.graphql.schema import schema
from app.routes.auth import auth_router

app = FastAPI()

# Integrar GraphQL
graphql_app = GraphQL(schema)
app.add_route("/graphql", graphql_app)

# Rutas REST
app.include_router(auth_router, prefix="/auth")

@app.get("/")
def read_root():
    return {"message": "Welcome to SeniorThrive API"}
