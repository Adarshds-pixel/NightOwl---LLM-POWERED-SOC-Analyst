"""Live SOC replay: turns real captured Sysmon telemetry (backend/sample_logs/,
see app/demo/scenarios/) into a paced, "happening now" demo feed.

Two pieces:
  - timeline.py         pure timestamp-rebasing math, no DB/IO
  - scenario_loader.py  loads app/demo/scenarios/*.yml + their record files

The service layer (app/services/replay_service.py, demo_service.py) is what
actually touches the database; this package stays domain logic only, same
split as app/detection/ and app/mitre/.
"""
