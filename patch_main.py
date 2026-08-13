
with open("d:/Project26/Extension/backend/app/main.py", "r", encoding="utf-8") as f:
    content = f.read()

# Replace "sec": {**stage1_response["sec"], "da": None},
# with "sec": stage1_response["sec"],
content = content.replace(
    "\"sec\": {**stage1_response[\"sec\"], \"da\": None},",
    "\"sec\": stage1_response[\"sec\"],"
)

with open("d:/Project26/Extension/backend/app/main.py", "w", encoding="utf-8") as f:
    f.write(content)

print("Success main")

