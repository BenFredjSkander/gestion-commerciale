package com.projet.stock.repository;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.projet.stock.model.Ordre;
@Repository
public interface OrdreRepository extends JpaRepository<Ordre, Long>{

}
