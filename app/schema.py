import strawberry

@strawberry.type
class Query:
    hello: str = "Hello, SeniorThrive!"

schema = strawberry.Schema(query=Query)
