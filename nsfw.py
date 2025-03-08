#!/user/bin/env python3.12
import subprocess
from mitmproxy import http
from mitmproxy import ctx
import tempfile
import json
from constants.blacklist import blacklist
from utils.get_random_image import getRandomImage
import re
import base64
from pathlib import Path

def checkNSFWPredictions(predictions, level):
  isNSFW = False;
  for prediction in predictions:
    category = prediction['category']
    if (category == 'hentai' or category == 'porn' or category == 'sexy'):
      isNSFW = prediction['probability'] > level

      if (isNSFW): break
  return isNSFW

class NSFWDetector:
    def load(self, loader):
        loader.add_option(
          name="command",
          typespec=str,
          help="You will want that this command run when we wanted to classify image with IA. It should include <dir>.",
          default=""
        )
        loader.add_option(
           name="level",
           typespec=str,
           help="Depending of the command you use to classify the image, you will get different measure types. Add here the min value accepted to consider it nsfw.",
           default="0.3"
        )

    def request(self, flow: http.HTTPFlow) -> None:
      urlProtocolRegExp = "(https|http)?(://)?(www\.)?[/]*"
      # Some ads add link of target website in the referrer header. So we can block ads for specific pages
      referer_url = re.sub(urlProtocolRegExp, "", (flow.request.headers.get('Referer') or ""))
      site_url = re.sub(urlProtocolRegExp, "", flow.request.pretty_host)
      flow.request.headers["x-blacklisted-site"] = str(site_url in blacklist or (len(referer_url) > 0 and referer_url in blacklist))

    def response(self, flow: http.HTTPFlow) -> None:
      if (flow.response.headers.get("Content-Type", "").startswith("video")):
        if (flow.request.headers.get('x-blacklisted-site') == 'True'):
          flow.response.content = None
          flow.response.status_code = 403
          flow.response.reason = b"Forbidden"
          return

      elif (flow.response.headers.get("Content-Type", "").startswith("image")):
        if (flow.request.headers.get('x-blacklisted-site') == 'True'):
          flow.response.content = getRandomImage();
          flow.response.status_code = 403
          flow.response.headers["content-type"] = "image/jpg"
          return

        if (len(ctx.options.command) == 0):
          return

        with tempfile.NamedTemporaryFile(delete_on_close=True,delete=True) as tempFile:
          tempFile.write(flow.response.content);

          level = float(ctx.options.level)
          command = ctx.options.command.replace('<dir>', tempFile.name);
          commandArr = command.split(' ');
          result = subprocess.run(commandArr, capture_output=True);

          if (result.stderr):
            print("Error processing image: ", result.stderr)
            return

          if (result.stdout):
              jsonResult = json.loads(result.stdout)

              print('level: ', level)
              isNSFW = jsonResult['has_nudity'] == True or checkNSFWPredictions(jsonResult['predictions'], level)

              if (isNSFW):
                flow.response.content = getRandomImage();
                flow.response.headers["content-type"] = "image/jpg"

      else:
        if (flow.request.headers.get('x-blacklisted-site') == 'True'):
          flow.response.content = None
          flow.response.status_code = 403
          flow.response.reason = b"Forbidden"
          return
        images = re.findall(rb'image\/([a-zA-Z]+)\;base64\,([a-zA-Z0-9\+\\\/\=]+)[\"\' ]', flow.response.content)
        if len(images) > 0:
          images = list(set(images))
          print(f'inspecting {len(images)} base64 images')
          for i, (ext, rawb64) in enumerate(images):
            try:
              file_content=base64.b64decode(rawb64)
              Path(f"/logs/{flow.client_conn.peername[0]}/").mkdir(parents=True, exist_ok=True)
              imagePath = f"/logs/{flow.client_conn.peername[0]}/{flow.id}-{i}.{ext.decode('utf-8', 'ignore')}"
              with open(imagePath,"ab") as tempFile:
                tempFile.write(file_content)
                level = float(ctx.options.level)
                command = ctx.options.command.replace('<dir>', tempFile.name);
                commandArr = command.split(' ');
                result = subprocess.run(commandArr, capture_output=True);

                if (result.stderr):
                  print("Error processing image: ", result.stderr)
                  Path(imagePath).unlink()
                  continue

                if (result.stdout):
                    jsonResult = json.loads(result.stdout)
                    isNSFW = jsonResult['has_nudity'] == True or checkNSFWPredictions(jsonResult['predictions'], level)
                    if (isNSFW):
                      print('usfw base64 image: ', imagePath)
                    else:
                      Path(imagePath).unlink()
            except Exception as e:
                print(str(e))


addons = [NSFWDetector()]