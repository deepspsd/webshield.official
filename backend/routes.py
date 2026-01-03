def register_routes(app):
    from .api_routes import api_router
    from .auth import auth_router
    from .chatbot_routes import chatbot_router
    from .db import db_router
    from .export import export_router
    from .frontend_routes import frontend_router
    from .scan import scan_router
    from .translation_routes import translation_router

    # Include all routers
    app.include_router(scan_router)
    app.include_router(export_router)
    app.include_router(db_router)
    app.include_router(auth_router)
    app.include_router(frontend_router)
    app.include_router(api_router)
    app.include_router(translation_router)
    app.include_router(chatbot_router)
