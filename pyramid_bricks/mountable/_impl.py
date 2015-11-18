import venusian
from zope.interface import Interface, implementer


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
                if current.shadowed is None:
                    current.shadowed = DirectoryFactory()
                current = current.shadowed
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

    def mount(self, name, dict_factory):
        shadowed = self.subtrees.get(name, None)

        if shadowed is not None and not isinstance(shadowed, DirectoryFactory):
            raise ConflictMountPoint

        def factory(*args, **kwargs):
            dict_like = dict_factory(*args, **kwargs)
            if hasattr(dict_like, 'next_factory'):
                setattr(dict_like, 'next_factory', factory.shadowed)
            return dict_like
        factory.shadowed = shadowed

        self.subtrees[name] = factory

    def __call__(self, request):
        return Directory(self, request)


class Directory:
    def __init__(self, factory: DirectoryFactory, request):
        self._factory = factory
        self._request = request
        self.next_factory = lambda req: {}

    def __getitem__(self, key):
        if key in self._factory.subtrees:
            return self._factory.subtrees[key](self._request)
        else:
            return self.next_factory(self._request)[key]


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
        root = request.registry.getUtility(IRoot)  # type: IRoot
        return root.lookup(path)(request)
    return factory


def _directive_mount(config, path, dict_factory):
    def do_mount():
        root = config.registry.getUtility(IRoot)  # type: IRoot
        root.mount(path, dict_factory)
    config.action(None, do_mount, order=1)


def _setup_root(config):
    def action():
        config.registry.registerUtility(Root(), IRoot)
    return action()


def includeme(config):
    config.add_directive('mount', _directive_mount)
    config.action('setup_mountable', _setup_root(config), order=0)
