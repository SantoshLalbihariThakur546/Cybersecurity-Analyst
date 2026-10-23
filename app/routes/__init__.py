def register_blueprints(app):
    from . import (auth_routes, reference_routes, threats, incidents, policy, awareness, vulns, audits,
                   dashboard, reports, admin)
    for mod in (auth_routes, reference_routes, threats, incidents, policy, awareness, vulns, audits, dashboard, reports, admin):
        app.register_blueprint(mod.bp)
