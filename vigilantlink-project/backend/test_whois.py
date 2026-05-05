import asyncio
import asyncwhois

async def main():
    query_string, parsed_dict = await asyncwhois.aio_whois("apple.com")
    print(type(parsed_dict))
    print(parsed_dict.get('created'))

asyncio.run(main())
