import os

base_dir = os.path.abspath(os.path.dirname(__file__))
sql_url = os.path.join(base_dir, 'data.sqlite')


class Config:
    SQLALCHEMY_COMMIT_ON_TEARDOWN = False

    @staticmethod
    def init_app(app):
        pass


# 开发环境的配置
class DevelopmentConfig(Config):
    DEBUG = True

    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + sql_url


# 测试环境的配置
class TestingConfig(Config):
    TESTING = True

    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + sql_url


# 生产环境的配置
class ProductionConfig(Config):
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + sql_url


config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}

