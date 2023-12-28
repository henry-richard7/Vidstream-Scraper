from Modules import Scraper


scarper = Scraper.VidstreamScraper()

search_results = scarper.search("City hunter")
print(search_results)
