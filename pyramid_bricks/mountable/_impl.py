import venusian
import inspect
from zope.interface import Interface, implementer
from zope.proxy import ProxyBase, getProxiedObject, non_overridable
from pyramid.httpexceptions import HTTPNotFound
from functools import partial


class IRoot(Interface):
    def mount(self, path, dict_factory):
        pass

    def lookup(self, path):
        pass


@implementer(IRoot)
class Root:
    def __init__(self):
        self._hyper_root = DirectoryFactory()
        self._hyper_root.subtrees['root'] = DirectoryFactory()

    def mount(self, path, dict_factory):
        comps = ['root'] + [comp for comp in path.split('/') if len(comp)]
        current = self._hyper_root
        for comp in comps[:-1]:
            if comp not in current.subtrees:
                current.subtrees[comp] = DirectoryFactory()
            current = current.subtrees[comp]
            while not isinstance(current, DirectoryFactory):
                if current.mounted is None:
                    current.mounted = DirectoryFactory()
                current = current.mounted
        current.mount(comps[-1], dict_factory)

    def lookup(self, path):
        comps = ['root'] + [comp for comp in path.split('/') if len(comp)]
        current = self._hyper_root
        for comp in comps:
            current = current.subtrees[comp]
        return current


class ConflictMountPoint(BaseException):
    pass


class DirectoryFactory:
    def __init__(self):
        self.subtrees = {}

    @staticmethod
    def _reify(func):
        if func is None:
            return None

        created = False
        value = None

        def nfunc(*args, **kwargs):
            nonlocal created, value
            if not created:
                value = func(*args, **kwargs)
                print('create value')
                created = True
            return value
        return nfunc

    def mount(self, name, dict_factory):
        mounted_factory = self.subtrees.get(name, None)

        if mounted_factory is not None and not isinstance(mounted_factory, DirectoryFactory):
            raise ConflictMountPoint

        def create_dict_factory_dyanmic_proxy(dict_factory):
            def proxied_dict_factory(*args, **kwargs):
                dict_like = dict_factory(*args, **kwargs)
                if isinstance(dict_like, _SimpleMountable):
                    return dict_like
                else:
                    return make_mountable_dynamically(dict_like)
            return proxied_dict_factory

        dict_factory = create_dict_factory_dyanmic_proxy(dict_factory)

        def factory(*args, **kwargs):
            dict_like = dict_factory(*args, **kwargs)
            if hasattr(dict_like, '_mounted_factory') and factory.mounted is not None:
                setattr(dict_like, '_mounted_factory', partial(factory.mounted, *args, **kwargs))
            return dict_like
        factory.mounted = DirectoryFactory._reify(mounted_factory)

        self.subtrees[name] = factory

    def __call__(self, request):
        return Directory(self, request)


class _SimpleMountable:
    def __init__(self, impl):
        self.__impl = impl
        self._mounted_factory = lambda: {}

    def __getitem__(self, key):
        try:
            return _hint_location(self._mounted_factory()[key], key, self)
        except KeyError:
            return _hint_location(self.__impl[key], key, self)


class Directory:
    def __init__(self, factory: DirectoryFactory, request):
        self._factory = factory
        self._request = request
        self._mounted_factory = lambda: {}

        self.__name__ = None
        self.__parent__ = None

    def __getitem__(self, key):
        if key in self._factory.subtrees:
            return _hint_location(self._factory.subtrees[key](self._request), key, self)
        else:
            return _hint_location(self._mounted_factory()[key], key, self)

    def __setloc__(self, name, parent):
        self.__name__ = name
        self.__parent__ = parent


def mount(*paths):
    def deco(dict_factory):
        def callback(scanner, name, ob):
            for path in paths:
                scanner.config.mount(path, dict_factory)
        venusian.attach(dict_factory, callback, 'mount')
        return dict_factory
    return deco


def subtree_factory(path):
    def factory(request):
        try:
            root = request.registry.getUtility(IRoot)  # type: Root
            factory_impl = root.lookup(path)
        except KeyError:
            raise HTTPNotFound
        return _hint_location(factory_impl(request), None, None)
    return factory


def make_mountable(constructor):
    if issubclass(constructor, _SimpleMountable):
        return constructor

    class Proxy(_SimpleMountable, constructor):
        def __init__(self, *args, **kwargs):
            constructor.__init__(self, *args, **kwargs)
            _SimpleMountable.__init__(self, super(constructor, self))

    return Proxy


def make_mountable_dynamically(instance):
    class Proxy(ProxyBase):
        __slots__ = '_mounted_factory'

        @non_overridable
        def __getitem__(self, key):
            try:
                return _hint_location(self._mounted_factory()[key], key, self)
            except KeyError:
                return _hint_location(getProxiedObject(self)[key], key, self)

    instance = Proxy(instance)
    instance._mounted_factory = lambda: {}
    return instance


def _hint_location(resource, name, parent):
    if resource is not None:
        setloc = getattr(resource, '__setloc__', None)
        if setloc is not None:
            setloc(name, parent)
    return resource


def _directive_mount(config, path, dict_factory):
    def do_mount():
        root = config.registry.getUtility(IRoot)  # type: Root
        root.mount(path, dict_factory)
    config.action(None, do_mount, order=1)


def _setup_root(config):
    def action():
        config.registry.registerUtility(Root(), IRoot)
    return action()


def includeme(config):
    config.add_directive('mount', _directive_mount)
    config.action('setup_mountable', _setup_root(config), order=0)
