-- Projeto fictício do TS Manager: criaturas de exemplo.

local creatures = {}

creatures.rat = {
  health = 20,
  experience = 5,
  loot = { "cheese" },
}

creatures.wolf = {
  health = 25,
  experience = 18,
  loot = { "meat", "wolf paw" },
}

creatures.orc = {
  health = 70,
  experience = 25,
  loot = { "axe", "gold coin" },
}

function creatures.get(name)
  return creatures[name]
end

return creatures
