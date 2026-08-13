
with open("d:/Project26/Extension/backend/app/main.py", "r", encoding="utf-8") as f:
    content = f.read()

content = content.replace("from .routers import domain_age_router\n", "")
content = content.replace("app.include_router(domain_age_router.router)\n", "")

with open("d:/Project26/Extension/backend/app/main.py", "w", encoding="utf-8") as f:
    f.write(content)

print("Success main router fix")

