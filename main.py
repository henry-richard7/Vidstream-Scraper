from Modules import VidstreamScraper

scarper = VidstreamScraper()

query = input("Show to search?: ")
search_results = scarper.search(query)

print(f"Search Results For: {query} ({len(search_results)} Results!)")
for i, result in enumerate(search_results):
    print(f"[{i}] - {result['title']}")

result_choice = int(input("Your Choice > "))
selected_show = search_results[result_choice]

episodes = scarper.episodes(selected_show["href"])

for i, episode in enumerate(episodes):
    print(f"[{i}] - {episode['title']}")

episode_choice = int(input("Your Choice > "))
selected_episode = episodes[episode_choice]

print(scarper.default_server(selected_episode["href"]))
