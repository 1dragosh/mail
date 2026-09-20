import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import app

bounced, complained = app.poll_inboxroad_events()
print("inboxroad: bounces=%d complaints=%d" % (bounced, complained))
