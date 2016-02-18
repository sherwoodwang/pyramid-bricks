from zope.proxy import ProxyBase, non_overridable, getProxiedObject
from zope.interface import Interface, implementer
import venusian


class MergedDirectoryFactory:
    def __init__(self):
        self._simulate = None
        self.subfactories = {}

    def mount(self, directory_factory):
        self._simulate = directory_factory

    def __call__(self, *args):
        directory = ProducingDirectory(self.subfactories, *args)

        if self._simulate is not None:
            merged_directory = MergedDirectory(self._simulate(*args))
            setattr(merged_directory, '_attached', directory)
            directory = merged_directory

        return directory


class ProducingDirectory:
    def __init__(self, factories, *args):
        self.factories = factories
        self.arguments = args
        self.entries = {}

    def __getitem__(self, key):
        if key in self.factories:
            if key not in self.entries:
                self.entries[key] = self.factories[key](*self.arguments)
            return self.entries[key]
        raise KeyError


class MergedDirectory(ProxyBase):
    __slots__ = ('_attached', )

    @non_overridable
    def __getitem__(self, key):
        try:
            obj = getProxiedObject(self)
            if not hasattr(obj, '__getitem__'):
                raise KeyError
            return obj[key]
        except KeyError:
            return self._attached[key]


class Tree:
    def __init__(self):
        self.root = MergedDirectoryFactory()

    def mount(self, path: str, directory_factory):
        self.lookup(path).mount(directory_factory)

    def lookup(self, path: str):
        path = [comp for comp in path.split('/') if len(comp)]
        cur = self.root
        for comp in path:
            if comp not in cur.subfactories:
                cur.subfactories[comp] = MergedDirectoryFactory()
            cur = cur.subfactories[comp]
        return cur


def mount(*paths):
    def deco(dict_factory):
        def callback(scanner, name, ob):
            for path in paths:
                scanner.config.mount(path, dict_factory)
        venusian.attach(dict_factory, callback, 'mount')
        return dict_factory
    return deco


class IRoot(Interface):
    def mount(self, path, directory_factory):
        pass

    def lookup(self, path):
        pass


@implementer(IRoot)
class Root(Tree):
    pass


def _setup_root(config):
    def action():
        config.registry.registerUtility(Root(), IRoot)
    return action()


def subtree_factory(path):
    real_factory = None

    def factory(*args):
        request = args[-1]
        nonlocal real_factory
        if real_factory is None:
            real_factory = request.registry.getUtility(IRoot).lookup(path)
        return real_factory(*args)

    return factory


def _directive_mount(config, path, dict_factory):
    def do_mount():
        root = config.registry.getUtility(IRoot)  # type: IRoot
        root.mount(path, dict_factory)
    config.action(None, do_mount, order=1)


def includeme(config):
    config.add_directive('mount', _directive_mount)
    config.action('setup_mountable', _setup_root(config), order=0)