package modules

type Registry struct{ modules []Module }

func (r *Registry) Register(module Module) { r.modules = append(r.modules, module) }
func (r *Registry) All() []Module          { return append([]Module(nil), r.modules...) }
func (r *Registry) ByCategory(category Category) []Module {
	return r.filter(func(module Module) bool { return module.Category() == category })
}

func (r *Registry) ByToolFamily(family ToolFamily) []Module {
	return r.filter(func(module Module) bool { return module.ToolFamily() == family })
}

func (r *Registry) ByProtocol(protocol Protocol) []Module {
	return r.filter(func(module Module) bool { return module.Protocol() == protocol })
}

func (r *Registry) ModulesForScope(family ToolFamily, category Category, protocol Protocol) []Module {
	return r.filter(func(module Module) bool {
		return module.ToolFamily() == family && module.Category() == category && module.Protocol() == protocol
	})
}

func (r *Registry) filter(match func(Module) bool) []Module {
	filtered := make([]Module, 0)
	for _, module := range r.modules {
		if match(module) {
			filtered = append(filtered, module)
		}
	}
	return filtered
}
