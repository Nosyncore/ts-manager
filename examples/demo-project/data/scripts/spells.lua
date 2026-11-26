-- Projeto fictício do TS Manager: magias de exemplo.
-- Linhas não adjacentes são usadas nos testes de merge limpo.

local spells = {}

spells.light = {
  words = "utevo lux",
  mana = 20,
  level = 8,
}

spells.heal = {
  words = "exura",
  mana = 25,
  level = 9,
}

spells.fireball = {
  words = "exori flam",
  mana = 40,
  level = 15,
}

function spells.get(name)
  return spells[name]
end

return spells
