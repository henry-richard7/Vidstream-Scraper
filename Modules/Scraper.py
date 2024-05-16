import sys

sys.path.append("Modules")
from bs4 import BeautifulSoup
import requests
import re
from urllib.parse import urlparse, parse_qs

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import b64encode, b64decode

from json import loads, load

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.0.43 Safari/537.36"
}


class VideoSourceNotFound(Exception):
    def __init__(self, message="Video Source Not Found"):
        self.message = message
        super().__init__(self.message)


class VidstreamScraper:
    def __init__(self, mode: str = "kdrama"):
        """_summary_
        This class scrapes shows from vidstream based sites.

        Args:
            mode (str, optional): _description_. Defaults to "kdrama".
            available_modes:
                anime  -> Anime  contents
                kdrama -> Kdrama contents

        """
        self.mode = mode
        with open("Modules/keys.json", "r") as keys_file:
            config: dict = load(keys_file)

        final_config = config.get(mode.lower())
        self.base_url, self.encode_key, self.decrypt_key, self.iv = (
            final_config.values()
        )

        self.encode_key = self.encode_key.encode() if self.encode_key else None
        self.decrypt_key = self.decrypt_key.encode() if self.decrypt_key else None
        self.iv = self.iv.encode() if self.iv else None
        print(self.encode_key)

    def encrypt(self, message, key=None):
        iv = self.iv
        # Pad the message to be a multiple of 16 bytes
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message) + padder.finalize()

        # Create an AES cipher object with the key, CBC mode, and the provided IV
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Encrypt the padded data
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # Return the base64-encoded ciphertext
        return b64encode(ciphertext).decode("utf-8")

    def decrypt(self, ciphertext, key=None):
        iv = self.iv

        # Decode the base64-encoded ciphertext
        ciphertext = b64decode(ciphertext)

        # Create an AES cipher object with the key, CBC mode, and the provided IV
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the ciphertext
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Unpad the decrypted data
        unpadder = padding.PKCS7(128).unpadder()
        message = unpadder.update(padded_data) + unpadder.finalize()

        # Return the decrypted message
        return message.decode("utf-8")

    def recently_added(self, page_number: int = 1):
        """
        Returns a list of recently added shows.
        @page_number: input of page number, by default set to 1
        """

        result = []
        next_page_number = page_number + 1
        page = requests.get(
            f"{self.base_url}/?page={page_number}",
            headers=HEADERS,
            allow_redirects=True,
        )
        soup = BeautifulSoup(page.content, "html.parser")
        shows = soup.find("ul", class_="listing items")

        for show in shows.find_all("li"):
            result.append(
                {
                    "title": re.sub(
                        r"Episode.\d+",
                        "",
                        show.select_one("div[class='name']").get_text().strip(),
                    ),
                    "image": show.find("img").get("src"),
                    "href": f'{self.base_url}{show.find("a").get("href")}',
                    "date": show.find("span", class_="date").get_text(),
                }
            )
        return {"dramas": result, "next_page": next_page_number}

    def search(self, query: str) -> list:
        """
        Returns a list of shows matching the query.
        @query: Name of show to search.
        """

        result = []

        page = requests.get(
            f"{self.base_url}/search.html?keyword={query}",
            headers=HEADERS,
            allow_redirects=True,
        )
        soup = BeautifulSoup(page.content, "html.parser")
        shows = soup.find("ul", class_="listing items")

        for show in shows.find_all("li"):
            result.append(
                {
                    "title": re.sub(
                        r"Episode.\d+",
                        "",
                        show.select_one("div[class='name']").get_text().strip(),
                    ),
                    "image": show.find("img").get("src"),
                    "href": f'{self.base_url}{show.find("a").get("href")}',
                    "date": show.find("span", class_="date").get_text(),
                }
            )
        return result

    def episodes(self, url: str) -> list:
        """
        Returns a list of episodes for a show.
        """

        result = []

        page = requests.get(url, headers=HEADERS, allow_redirects=True)
        soup = BeautifulSoup(page.content, "html.parser")
        episodes = soup.find("ul", class_="listing items lists")

        for episode in episodes.find_all("li"):
            result.append(
                {
                    "title": episode.select_one("div[class='name']").get_text().strip(),
                    "image": episode.find("img").get("src"),
                    "href": f'{self.base_url}{episode.find("a").get("href")}',
                    "date": episode.find("span", class_="date").get_text(),
                }
            )
        return result

    def streamSB(self, url: str) -> str:
        """
        Returns the video URL for an episode for streamSB servers.
        """
        page = requests.get(url, headers=HEADERS, allow_redirects=True)
        soup = BeautifulSoup(page.content, "html.parser")
        video = soup.find("div", class_="play-video")

        first_iframe = f'https:{video.find("iframe").get("src")}'
        second_iframe = requests.get(first_iframe, headers=HEADERS)
        soup = BeautifulSoup(second_iframe.content, "html.parser")

        sbplay_url = (
            soup.find("ul", class_="list-server-items")
            .find("li", attrs={"data-video": re.compile(r"stream")})
            .get("data-video")
        )

        parsed_url = urlparse(sbplay_url)
        domain = parsed_url.netloc
        id_ = parsed_url.path.split("/")[-1]
        id_ = bytearray(id_, "utf-8")

        master_url = (
            f"https://{domain}/sources48/7c7c{id_.hex()}7c7c7c7c73747265616d7362/"
        )

        headers = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "watchsb": "sbstream",
            "accept-encoding": "gzip",
        }

        last_link = requests.get(
            master_url, headers=headers, allow_redirects=True, verify=False
        )
        last_link = last_link.json()["stream_data"]["file"]
        return last_link

    def fembed(self, url: str) -> str:
        """
        Returns the video URL for an episode for fembed servers.
        """

        page = requests.get(url, headers=HEADERS)
        soup = BeautifulSoup(page.content, "html.parser")
        video = soup.find("div", class_="play-video")

        first_iframe = f'https:{video.find("iframe").get("src")}'
        second_iframe = requests.get(first_iframe, headers=HEADERS)
        soup = BeautifulSoup(second_iframe.content, "html.parser")

        sbplay_url = (
            soup.find("ul", class_="list-server-items")
            .find("li", attrs={"data-video": re.compile(r"fembed")})
            .get("data-video")
        )
        headers = {
            "Referer": sbplay_url,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0",
        }
        api_id = urlparse(sbplay_url).path.split("/")[-1]
        api_host = urlparse(sbplay_url).netloc
        api_url = f"https://{api_host}/api/source/{api_id}"
        final_link = requests.post(api_url, headers=headers).json()["data"][-1]["file"]
        return final_link

    def default_server(self, url: str) -> str:
        """
        Returns the video URL for an episode for streamSB servers.
        """
        page = requests.get(url, headers=HEADERS, allow_redirects=True)
        soup = BeautifulSoup(page.content, "html.parser")

        iframe_url = f"https:{soup.find('iframe').attrs.get('src')}"
        parsed_url = urlparse(iframe_url)

        parsed_parameters = parse_qs(parsed_url.query)
        parsed_parameters = {k: v[0] for k, v in parsed_parameters.items()}

        if parsed_parameters.get("id"):

            iframe_response = requests.get(
                iframe_url,
                headers=HEADERS,
                allow_redirects=True,
            )
            iframe_soup = BeautifulSoup(iframe_response.content, "html.parser")
            encrypted_data = iframe_soup.find(
                "script",
                attrs={"data-name": "episode" if self.mode == "anime" else "crypto"},
            ).attrs.get("data-value")

            decrypted_data = self.decrypt(encrypted_data, key=self.encode_key)

            original_id = decrypted_data.split("&")[0]
            encrypted_id = self.encrypt(original_id.encode(), self.encode_key)

            ajax_encrypt_url = (
                self.base_url
                + "encrypt-ajax.php"
                + "?id="
                + encrypted_id
                + "&alias="
                + decrypted_data
            )

            rr = requests.get(
                url=ajax_encrypt_url,
                headers={**HEADERS, "X-Requested-With": "XMLHttpRequest"},
            )
            if rr.status_code == 200:
                j_data = rr.json()
                encrupted_data = j_data["data"]
                decrypted_data = self.decrypt(encrupted_data, key=self.decrypt_key)

                parsed_json = loads(decrypted_data)
                return parsed_json
            else:
                raise VideoSourceNotFound()

        elif parsed_parameters.get("slug"):
            s_url = (
                f"{self.base_url}/streaming.php?slug={parsed_parameters.get('slug')}"
            )
            response = requests.get(s_url, allow_redirects=True)
            soup = BeautifulSoup(response.content, "html.parser")

            javascript_code = soup.select_one("script:nth-child(4)").text
            pattern = r'file:"(.*?)"'
            match = re.search(pattern, javascript_code, re.DOTALL)

            if match:
                file_link = match.group(1)
                result = {
                    "source": [
                        {"file": file_link},
                    ]
                }
                return result
            else:
                raise Exception("Unable to fetch Dircet Link!.")
