
import re

with open("d:/Project26/Extension/extension/scripts/background.js", "r", encoding="utf-8") as f:
    content = f.read()

# Pattern to remove the get_domain_age block
pattern = r"\s*if \(request\.action === \"get_domain_age\"\).*?return true;\s*}"
content = re.sub(pattern, "", content, flags=re.DOTALL)

with open("d:/Project26/Extension/extension/scripts/background.js", "w", encoding="utf-8") as f:
    f.write(content)

print("Success bg")

